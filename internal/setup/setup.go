package setup

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"cove/internal/config"
)

type setupError struct {
	code int
	msg  string
}

func (e setupError) Error() string {
	return e.msg
}

func (e setupError) ExitCode() int {
	return e.code
}

type invokingUser struct {
	UID      int
	GID      int
	Name     string
	Home     string
	viaSudo  bool
	lookupID string
}

func Run(args []string) error {
	fs := flag.NewFlagSet("cove setup", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	help := fs.Bool("help", false, "show help")
	if err := fs.Parse(args); err != nil {
		return setupError{code: 64, msg: err.Error()}
	}
	if *help {
		fmt.Fprintln(os.Stderr, "usage: cove setup")
		return nil
	}

	u, err := currentInvokingUser()
	if err != nil {
		return err
	}
	changed := false
	notes := []string{}
	if n, err := ensureUserArtifacts(u); err != nil {
		return err
	} else {
		notes = append(notes, n...)
		for _, note := range n {
			if strings.Contains(note, "created") || strings.Contains(note, "generated") {
				changed = true
			}
		}
	}

	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, _ = filepath.EvalSymlinks(exe)
	probeErr := probeUsernsAs(u, exe)
	if probeErr != nil {
		fmt.Fprintf(os.Stderr, "cove setup: userns probe before AppArmor grant failed: %v\n", probeErr)
		if err := runAppArmorStep(exe); err != nil {
			return err
		}
		changed = true
		notes = append(notes, "loaded AppArmor userns profile")
	}
	if err := probeUsernsAs(u, exe); err != nil {
		return setupError{code: 77, msg: fmt.Sprintf("cove setup: userns probe still fails after setup: %v", err)}
	}

	certPath := filepath.Join(u.Home, ".config", "cove", "ca.pem")
	fp, err := caFingerprint(certPath)
	if err != nil {
		return err
	}
	configPath := filepath.Join(u.Home, ".config", "cove", "config.toml")
	if _, err := config.Load(configPath); err != nil {
		return setupError{code: 78, msg: fmt.Sprintf("seed config did not validate: %v", err)}
	}

	for _, note := range notes {
		fmt.Fprintf(os.Stderr, "cove setup: %s\n", note)
	}
	if !changed {
		fmt.Fprintln(os.Stderr, "cove setup: no changes")
	}
	fmt.Fprintf(os.Stderr, "cove is ready: userns ok; CA SHA-256 %s; config %s\n", fp, configPath)
	return nil
}

func ApparmorOnly() error {
	if os.Geteuid() != 0 {
		return setupError{code: 77, msg: "cove __apparmor must run as root"}
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, _ = filepath.EvalSymlinks(exe)
	profile := fmt.Sprintf(`abi <abi/4.0>,
include <tunables/global>

profile cove %s flags=(unconfined) {
  userns,
  include if exists <local/cove>
}
`, exe)
	if err := os.WriteFile("/etc/apparmor.d/cove", []byte(profile), 0644); err != nil {
		return err
	}
	cmd := exec.Command("apparmor_parser", "-r", "/etc/apparmor.d/cove")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("apparmor_parser: %w", err)
	}
	return nil
}

func ProbeUsernsSelf() error {
	cmd := exec.Command("/bin/true")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS |
			syscall.CLONE_NEWPID | syscall.CLONE_NEWNET |
			syscall.CLONE_NEWIPC | syscall.CLONE_NEWUTS,
		UidMappings: []syscall.SysProcIDMap{{
			ContainerID: 0,
			HostID:      os.Getuid(),
			Size:        1,
		}},
		GidMappings: []syscall.SysProcIDMap{{
			ContainerID: 0,
			HostID:      os.Getgid(),
			Size:        1,
		}},
		GidMappingsEnableSetgroups: false,
	}
	if err := cmd.Run(); err != nil {
		return err
	}
	return nil
}

func currentInvokingUser() (invokingUser, error) {
	uidText := os.Getenv("SUDO_UID")
	gidText := os.Getenv("SUDO_GID")
	name := os.Getenv("SUDO_USER")
	viaSudo := uidText != "" && gidText != ""
	if !viaSudo {
		uidText = strconv.Itoa(os.Getuid())
		gidText = strconv.Itoa(os.Getgid())
	}
	uid, err := strconv.Atoi(uidText)
	if err != nil {
		return invokingUser{}, fmt.Errorf("invalid uid %q: %w", uidText, err)
	}
	gid, err := strconv.Atoi(gidText)
	if err != nil {
		return invokingUser{}, fmt.Errorf("invalid gid %q: %w", gidText, err)
	}
	usr, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return invokingUser{}, err
	}
	if name == "" {
		name = usr.Username
	}
	return invokingUser{UID: uid, GID: gid, Name: name, Home: usr.HomeDir, viaSudo: viaSudo, lookupID: strconv.Itoa(uid)}, nil
}

func ensureUserArtifacts(u invokingUser) ([]string, error) {
	var notes []string
	dirs := []struct {
		path string
		mode os.FileMode
	}{
		{filepath.Join(u.Home, ".config", "cove"), 0700},
		{filepath.Join(u.Home, ".config", "cove", "secrets"), 0700},
		{filepath.Join(u.Home, ".local", "state", "cove"), 0700},
		{filepath.Join(u.Home, ".local", "state", "cove", "sessions"), 0700},
	}
	for _, d := range dirs {
		if _, err := os.Stat(d.path); errors.Is(err, os.ErrNotExist) {
			notes = append(notes, "created "+d.path)
		}
		if err := os.MkdirAll(d.path, d.mode); err != nil {
			return nil, err
		}
		if err := chmodChown(d.path, d.mode, u); err != nil {
			return nil, err
		}
	}

	certPath := filepath.Join(u.Home, ".config", "cove", "ca.pem")
	keyPath := filepath.Join(u.Home, ".config", "cove", "ca-key.pem")
	if _, certErr := os.Stat(certPath); certErr != nil {
		if !errors.Is(certErr, os.ErrNotExist) {
			return nil, certErr
		}
		if err := generateCA(certPath, keyPath, u); err != nil {
			return nil, err
		}
		notes = append(notes, "generated local CA")
	} else if _, keyErr := os.Stat(keyPath); keyErr != nil {
		if !errors.Is(keyErr, os.ErrNotExist) {
			return nil, keyErr
		}
		if err := generateCA(certPath, keyPath, u); err != nil {
			return nil, err
		}
		notes = append(notes, "regenerated incomplete local CA")
	} else {
		if err := chmodChown(certPath, 0644, u); err != nil {
			return nil, err
		}
		if err := chmodChown(keyPath, 0600, u); err != nil {
			return nil, err
		}
	}

	configPath := filepath.Join(u.Home, ".config", "cove", "config.toml")
	if _, err := os.Stat(configPath); errors.Is(err, os.ErrNotExist) {
		if err := os.WriteFile(configPath, []byte(config.DefaultConfig), 0600); err != nil {
			return nil, err
		}
		if err := chmodChown(configPath, 0600, u); err != nil {
			return nil, err
		}
		notes = append(notes, "created "+configPath)
	} else if err != nil {
		return nil, err
	} else if err := chmodChown(configPath, 0600, u); err != nil {
		return nil, err
	}
	return notes, nil
}

func chmodChown(path string, mode os.FileMode, u invokingUser) error {
	if err := os.Chmod(path, mode); err != nil {
		return err
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(path, u.UID, u.GID); err != nil {
			return err
		}
	}
	return nil
}

func generateCA(certPath, keyPath string, u invokingUser) error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return err
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "cove local CA",
			Organization: []string{"cove"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return err
	}
	if err := chmodChown(certPath, 0644, u); err != nil {
		return err
	}
	return chmodChown(keyPath, 0600, u)
}

func caFingerprint(certPath string) (string, error) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return "", fmt.Errorf("invalid CA PEM at %s", certPath)
	}
	sum := sha256.Sum256(block.Bytes)
	hexed := strings.ToUpper(hex.EncodeToString(sum[:]))
	parts := make([]string, 0, len(hexed)/2)
	for i := 0; i < len(hexed); i += 2 {
		parts = append(parts, hexed[i:i+2])
	}
	return strings.Join(parts, ":"), nil
}

func probeUsernsAs(u invokingUser, exe string) error {
	if os.Geteuid() == u.UID {
		return ProbeUsernsSelf()
	}
	cmd := exec.Command("sudo", "-u", "#"+strconv.Itoa(u.UID), "--", exe, "__probe_userns")
	cmd.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
	out, err := cmd.CombinedOutput()
	if err != nil {
		if len(out) > 0 {
			return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
		}
		return err
	}
	return nil
}

func runAppArmorStep(exe string) error {
	if os.Geteuid() == 0 {
		return ApparmorOnly()
	}
	cmd := exec.Command("sudo", exe, "__apparmor")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return setupError{code: 77, msg: fmt.Sprintf("failed to install AppArmor profile: %v", err)}
	}
	return nil
}
