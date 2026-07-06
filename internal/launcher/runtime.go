package launcher

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func resolveRuntimeMounts(agent string, explicit []string) ([]string, error) {
	home, _ := os.UserHomeDir()
	var mounts []string
	if auto, err := resolveAutoRuntimeMount(agent, home); err != nil {
		return nil, err
	} else if auto != "" {
		mounts = append(mounts, auto)
	}
	cfgMounts, err := parseRuntimeMounts(explicit, home)
	if err != nil {
		return nil, err
	}
	mounts = append(mounts, cfgMounts...)
	return dedupePaths(mounts), nil
}

func resolveAutoRuntimeMount(agent, home string) (string, error) {
	path, err := exec.LookPath(agent)
	if err != nil {
		return "", nil
	}
	pathAbs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	realAgent, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("resolve runtime for %q: %w", agent, err)
	}
	realAgent, err = filepath.Abs(realAgent)
	if err != nil {
		return "", err
	}
	if systemVisible(realAgent) {
		return "", nil
	}

	chosen := filepath.Dir(realAgent)
	node, err := resolveNodeInterpreter(realAgent)
	if err != nil {
		return "", err
	}
	if node != "" {
		chosen = interpreterToolchainDir(node)
		if !pathInside(chosen, realAgent) {
			chosen = commonAncestor(chosen, filepath.Dir(realAgent))
		}
	}
	if !systemVisible(pathAbs) && !pathInside(chosen, pathAbs) {
		chosen = commonAncestor(chosen, filepath.Dir(pathAbs))
	}
	if systemVisible(chosen) {
		return "", nil
	}
	if err := guardRuntimeMount(chosen, home); err != nil {
		return "", fmt.Errorf("cove: refusing to auto-mount runtime for agent %q: %s; add options.runtime_mount with a narrower tool directory or system-install the tool under /usr/local/bin", agent, err)
	}
	return filepath.Clean(chosen), nil
}

func resolveNodeInterpreter(agentPath string) (string, error) {
	f, err := os.Open(agentPath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	line, err := bufio.NewReader(f).ReadString('\n')
	if err != nil && line == "" {
		return "", nil
	}
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "#!") {
		return "", nil
	}
	fields := strings.Fields(strings.TrimSpace(strings.TrimPrefix(line, "#!")))
	if len(fields) == 0 {
		return "", nil
	}
	cmd := fields[0]
	if filepath.Base(cmd) == "env" {
		for _, arg := range fields[1:] {
			if arg == "" || strings.HasPrefix(arg, "-") || strings.Contains(arg, "=") {
				continue
			}
			if filepath.Base(arg) == "node" {
				return lookPathEval("node")
			}
			return "", nil
		}
		return "", nil
	}
	if filepath.Base(cmd) != "node" {
		return "", nil
	}
	if strings.ContainsRune(cmd, filepath.Separator) {
		real, err := filepath.EvalSymlinks(cmd)
		if err != nil {
			return "", err
		}
		return filepath.Abs(real)
	}
	return lookPathEval(cmd)
}

func lookPathEval(name string) (string, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("resolve interpreter %q: %w", name, err)
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("resolve interpreter %q: %w", name, err)
	}
	return filepath.Abs(real)
}

func interpreterToolchainDir(interpreter string) string {
	dir := filepath.Dir(interpreter)
	if filepath.Base(dir) == "bin" {
		parent := filepath.Dir(dir)
		if st, err := os.Stat(filepath.Join(parent, "lib")); err == nil && st.IsDir() {
			return parent
		}
	}
	return dir
}

func parseRuntimeMounts(entries []string, home string) ([]string, error) {
	var out []string
	for _, entry := range entries {
		path := entry
		if strings.HasPrefix(path, "~/") {
			path = filepath.Join(home, strings.TrimPrefix(path, "~/"))
		}
		if !filepath.IsAbs(path) {
			path = filepath.Join(home, path)
		}
		abs, err := filepath.Abs(path)
		if err != nil {
			return nil, err
		}
		real, err := filepath.EvalSymlinks(abs)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				fmt.Fprintf(os.Stderr, "cove: warning: runtime_mount %s does not exist; skipping\n", abs)
				continue
			}
			return nil, fmt.Errorf("runtime_mount %q: %w", entry, err)
		}
		st, err := os.Stat(real)
		if err != nil {
			return nil, fmt.Errorf("runtime_mount %q: %w", entry, err)
		}
		if !st.IsDir() {
			return nil, fmt.Errorf("runtime_mount %q must be a directory", entry)
		}
		if err := guardRuntimeMount(real, home); err != nil {
			return nil, fmt.Errorf("runtime_mount %q: %w", entry, err)
		}
		out = append(out, filepath.Clean(real))
	}
	return out, nil
}

func guardRuntimeMount(path, home string) error {
	path = filepath.Clean(path)
	switch path {
	case "/", "/home", "/root", "/etc":
		return fmt.Errorf("resolved toolchain dir %s is too broad", path)
	}
	if home != "" {
		home = filepath.Clean(home)
		if sameOrAncestor(path, home) {
			return fmt.Errorf("resolved toolchain dir %s would expose HOME or a parent of HOME", path)
		}
		if realHome, err := filepath.EvalSymlinks(home); err == nil {
			if realPath, err := filepath.EvalSymlinks(path); err == nil && sameOrAncestor(realPath, realHome) {
				return fmt.Errorf("resolved toolchain dir %s would expose HOME or a parent of HOME", path)
			}
		}
	}
	return nil
}

func systemVisible(path string) bool {
	return pathInside("/usr", filepath.Clean(path))
}

func pathInside(base, path string) bool {
	base = filepath.Clean(base)
	path = filepath.Clean(path)
	if base == path {
		return true
	}
	rel, err := filepath.Rel(base, path)
	return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func sameOrAncestor(path, child string) bool {
	return pathInside(path, child)
}

func commonAncestor(a, b string) string {
	a = filepath.Clean(a)
	b = filepath.Clean(b)
	for {
		if pathInside(a, b) {
			return a
		}
		next := filepath.Dir(a)
		if next == a {
			return a
		}
		a = next
	}
}

func dedupePaths(paths []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range paths {
		p = filepath.Clean(p)
		if p == "." || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}
