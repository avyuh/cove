package box

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func buildRoot(d Directives) (string, error) {
	if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		return "", fmt.Errorf("private root: %w", err)
	}
	root, err := os.MkdirTemp("/tmp", "cove-root.")
	if err != nil {
		return "", err
	}
	if err := syscall.Mount("tmpfs", root, "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV, "size=64m,mode=0755"); err != nil {
		return "", fmt.Errorf("tmpfs root: %w", err)
	}
	if err := bindRO("/usr", filepath.Join(root, "usr")); err != nil {
		return "", err
	}
	for link, target := range map[string]string{
		"bin":   "usr/bin",
		"sbin":  "usr/sbin",
		"lib":   "usr/lib",
		"lib64": "usr/lib",
	} {
		_ = os.Symlink(target, filepath.Join(root, link))
	}
	if err := synthEtc(root, d); err != nil {
		return "", err
	}
	if err := mountKernelFS(root); err != nil {
		return "", err
	}
	if err := mountScratch(root, d.TmpSize); err != nil {
		return "", err
	}
	if err := mountDev(root); err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Join(root, "work"), 0755); err != nil {
		return "", err
	}
	if err := syscall.Mount(d.Project, filepath.Join(root, "work"), "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
		return "", fmt.Errorf("bind /work: %w", err)
	}
	if err := syscall.Mount("", filepath.Join(root, "work"), "", syscall.MS_BIND|syscall.MS_REMOUNT|syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_REC, ""); err != nil {
		return "", fmt.Errorf("remount /work: %w", err)
	}
	if d.ProxySock != "" {
		if err := os.MkdirAll(filepath.Join(root, "proxy"), 0755); err != nil {
			return "", err
		}
		dst := filepath.Join(root, "proxy", "proxy.sock")
		if err := touch(dst, 0600); err != nil {
			return "", err
		}
		if err := syscall.Mount(d.ProxySock, dst, "", syscall.MS_BIND, ""); err != nil {
			return "", fmt.Errorf("bind proxy socket: %w", err)
		}
	}
	for _, m := range d.CredMount {
		if err := bindCred(root, m); err != nil {
			return "", err
		}
	}
	for _, src := range d.RuntimeMount {
		if err := bindRuntime(root, src); err != nil {
			return "", err
		}
	}
	if err := pivot(root); err != nil {
		return "", err
	}
	if err := os.Chdir("/work"); err != nil {
		return "", err
	}
	return root, nil
}

func synthEtc(root string, d Directives) error {
	etc := filepath.Join(root, "etc")
	if err := os.MkdirAll(filepath.Join(etc, "ssl", "certs"), 0755); err != nil {
		return err
	}
	files := map[string]string{
		"passwd":        "root:x:0:0:cove:/root:/bin/bash\n",
		"group":         "root:x:0:\n",
		"hosts":         "127.0.0.1 localhost\n::1 localhost\n",
		"hostname":      "cove\n",
		"resolv.conf":   "",
		"nsswitch.conf": "hosts: files\n",
		"gai.conf":      "precedence ::ffff:0:0/96 100\n",
		"machine-id":    "00000000000000000000000000000000\n",
	}
	if _, err := os.Stat(filepath.Join(root, "usr", "bin", "bash")); err != nil {
		files["passwd"] = "root:x:0:0:cove:/root:/bin/sh\n"
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(etc, name), []byte(body), 0644); err != nil {
			return err
		}
	}
	if err := os.WriteFile(filepath.Join(etc, "ssl", "certs", "cove-ca.pem"), d.CAPEM, 0644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(etc, "ssl", "certs", "cove-ca-bundle.pem"), d.CABundlePEM, 0644); err != nil {
		return err
	}
	for _, rel := range []string{"ssl/openssl.cnf", "services", "protocols", "localtime", "mime.types", "ld.so.cache"} {
		src := filepath.Join("/etc", rel)
		if _, err := os.Stat(src); err == nil {
			if err := bindRO(src, filepath.Join(etc, rel)); err != nil {
				return err
			}
		}
	}
	return nil
}

func mountKernelFS(root string) error {
	if err := os.MkdirAll(filepath.Join(root, "proc"), 0555); err != nil {
		return err
	}
	if err := syscall.Mount("proc", filepath.Join(root, "proc"), "proc", syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, ""); err != nil {
		return fmt.Errorf("mount /proc: %w", err)
	}
	sys := filepath.Join(root, "sys")
	if err := os.MkdirAll(filepath.Join(sys, "fs", "cgroup"), 0555); err != nil {
		return err
	}
	if err := syscall.Mount("tmpfs", sys, "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, "mode=0555"); err != nil {
		return fmt.Errorf("mount /sys tmpfs: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(sys, "fs", "cgroup"), 0555); err != nil {
		return err
	}
	if _, err := os.Stat("/sys/fs/cgroup"); err == nil {
		if err := bindCgroup("/sys/fs/cgroup", filepath.Join(sys, "fs", "cgroup")); err != nil {
			return err
		}
	}
	_ = syscall.Mount("", sys, "", syscall.MS_REMOUNT|syscall.MS_RDONLY|syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, "")
	return nil
}

func mountScratch(root, tmpSize string) error {
	mounts := []struct {
		path string
		data string
		mode os.FileMode
	}{
		{"root", "size=256m,mode=0700", 0700},
		{"tmp", "size=" + tmpSize + ",mode=1777", 01777},
		{"run", "size=16m,mode=0755", 0755},
		{"var/tmp", "size=64m,mode=1777", 01777},
	}
	if err := os.MkdirAll(filepath.Join(root, "var"), 0755); err != nil {
		return err
	}
	for _, m := range mounts {
		dst := filepath.Join(root, m.path)
		if err := os.MkdirAll(dst, m.mode); err != nil {
			return err
		}
		if err := syscall.Mount("tmpfs", dst, "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV, m.data); err != nil {
			return fmt.Errorf("mount /%s: %w", m.path, err)
		}
	}
	return nil
}

func mountDev(root string) error {
	dev := filepath.Join(root, "dev")
	if err := os.MkdirAll(dev, 0755); err != nil {
		return err
	}
	if err := syscall.Mount("tmpfs", dev, "tmpfs", syscall.MS_NOSUID|syscall.MS_NOEXEC, "size=4m,mode=0755"); err != nil {
		return fmt.Errorf("mount /dev: %w", err)
	}
	for _, name := range []string{"null", "zero", "full", "random", "urandom", "tty"} {
		src := filepath.Join("/dev", name)
		if _, err := os.Stat(src); err != nil {
			continue
		}
		dst := filepath.Join(dev, name)
		if err := touch(dst, 0666); err != nil {
			return err
		}
		if err := syscall.Mount(src, dst, "", syscall.MS_BIND, ""); err != nil {
			return fmt.Errorf("bind %s: %w", src, err)
		}
	}
	if err := os.MkdirAll(filepath.Join(dev, "pts"), 0755); err != nil {
		return err
	}
	if err := syscall.Mount("devpts", filepath.Join(dev, "pts"), "devpts", syscall.MS_NOSUID|syscall.MS_NOEXEC, "newinstance,ptmxmode=0666,mode=0620"); err != nil {
		return fmt.Errorf("mount devpts: %w", err)
	}
	_ = os.Symlink("pts/ptmx", filepath.Join(dev, "ptmx"))
	_ = os.Symlink("/proc/self/fd", filepath.Join(dev, "fd"))
	_ = os.Symlink("/proc/self/fd/0", filepath.Join(dev, "stdin"))
	_ = os.Symlink("/proc/self/fd/1", filepath.Join(dev, "stdout"))
	_ = os.Symlink("/proc/self/fd/2", filepath.Join(dev, "stderr"))
	if err := os.MkdirAll(filepath.Join(dev, "shm"), 01777); err != nil {
		return err
	}
	if err := syscall.Mount("tmpfs", filepath.Join(dev, "shm"), "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV, "size=64m,mode=1777"); err != nil {
		return fmt.Errorf("mount /dev/shm: %w", err)
	}
	return nil
}

func bindCred(root string, m CredMount) error {
	dst := filepath.Join(root, "root", m.Rel)
	if err := ensureMountpoint(m.Source, dst); err != nil {
		return err
	}
	if err := syscall.Mount(m.Source, dst, "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
		return fmt.Errorf("bind cred %s: %w", m.Source, err)
	}
	if !m.RW {
		if err := syscall.Mount("", dst, "", syscall.MS_BIND|syscall.MS_REMOUNT|syscall.MS_RDONLY|syscall.MS_REC, ""); err != nil {
			return fmt.Errorf("remount cred ro %s: %w", m.Source, err)
		}
	}
	return nil
}

func bindRuntime(root, src string) error {
	if !filepath.IsAbs(src) {
		return fmt.Errorf("runtime mount %s is not absolute", src)
	}
	dst := filepath.Join(root, src)
	if err := bindRO(src, dst); err != nil {
		return fmt.Errorf("runtime mount %s: %w", src, err)
	}
	return nil
}

func bindRO(src, dst string) error {
	if err := ensureMountpoint(src, dst); err != nil {
		return err
	}
	if err := syscall.Mount(src, dst, "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
		return fmt.Errorf("bind %s: %w", src, err)
	}
	if err := syscall.Mount("", dst, "", syscall.MS_BIND|syscall.MS_REMOUNT|syscall.MS_RDONLY|syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_REC, ""); err != nil {
		return fmt.Errorf("remount ro %s: %w", dst, err)
	}
	return nil
}

func bindCgroup(src, dst string) error {
	if err := ensureMountpoint(src, dst); err != nil {
		return err
	}
	if err := syscall.Mount(src, dst, "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
		return fmt.Errorf("bind %s: %w", src, err)
	}
	_ = syscall.Mount("", dst, "", syscall.MS_BIND|syscall.MS_REMOUNT|syscall.MS_RDONLY|syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_REC, "")
	return nil
}

func ensureMountpoint(src, dst string) error {
	st, err := os.Stat(src)
	if err != nil {
		return err
	}
	if st.IsDir() {
		return os.MkdirAll(dst, 0755)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	return touch(dst, 0644)
}

func touch(path string, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDONLY, mode)
	if err != nil {
		return err
	}
	return f.Close()
}

func pivot(root string) error {
	if err := os.Chdir(root); err != nil {
		return err
	}
	if err := os.Mkdir(".oldroot", 0700); err != nil {
		return err
	}
	if err := syscall.PivotRoot(root, filepath.Join(root, ".oldroot")); err != nil {
		return fmt.Errorf("pivot_root: %w", err)
	}
	if err := os.Chdir("/"); err != nil {
		return err
	}
	_ = syscall.Mount("", "/.oldroot", "", syscall.MS_REC|syscall.MS_PRIVATE, "")
	if err := syscall.Unmount("/.oldroot", syscall.MNT_DETACH); err != nil {
		return fmt.Errorf("detach oldroot: %w", err)
	}
	return os.Remove("/.oldroot")
}
