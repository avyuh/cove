package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Options Options        `toml:"options"`
	Allow   []string       `toml:"allow"`
	Inject  []InjectStanza `toml:"inject"`

	AllowRules []AllowRule `toml:"-"`
}

type Options struct {
	TmpSize        string   `toml:"tmp_size"`
	ProxyPort      int      `toml:"proxy_port"`
	Audit          bool     `toml:"audit"`
	CredMount      []string `toml:"cred_mount"`
	EnvPassthrough []string `toml:"env_passthrough"`
}

type InjectStanza struct {
	Host           string   `toml:"host"`
	HeaderName     string   `toml:"header_name"`
	HeaderTemplate string   `toml:"header_template"`
	Secret         string   `toml:"secret"`
	StripHeaders   []string `toml:"strip_headers"`
	DummyEnv       string   `toml:"dummy_env"`
	DummyValue     string   `toml:"dummy_value"`
	BaseURLEnv     string   `toml:"base_url_env"`
	BaseURLValue   string   `toml:"base_url_value"`
	ALPN           string   `toml:"alpn"`
	Mode           string   `toml:"mode"`

	Port int `toml:"-"`
}

type AllowRule struct {
	Pattern  string
	Host     string
	Wildcard bool
	Port     int
}

type rawConfig struct {
	Options rawOptions     `toml:"options"`
	Allow   []string       `toml:"allow"`
	Inject  []InjectStanza `toml:"inject"`
}

type rawOptions struct {
	Options
	Allow []string `toml:"allow"`
}

func Load(path string) (*Config, error) {
	if path == "" {
		path = DefaultPath()
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			data = []byte(DefaultConfig)
		} else {
			return nil, err
		}
	}
	return LoadBytes(data)
}

func LoadBytes(data []byte) (*Config, error) {
	raw := rawConfig{
		Options: rawOptions{Options: Options{
			TmpSize:   "256m",
			ProxyPort: 8080,
			Audit:     true,
		}},
	}
	if _, err := toml.Decode(string(data), &raw); err != nil {
		return nil, err
	}
	cfg := &Config{
		Options: raw.Options.Options,
		Allow:   raw.Allow,
		Inject:  raw.Inject,
	}
	if len(cfg.Allow) == 0 && len(raw.Options.Allow) > 0 {
		cfg.Allow = raw.Options.Allow
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func DefaultPath() string {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "cove", "config.toml")
}

func StateDir() string {
	base := os.Getenv("XDG_STATE_HOME")
	if base == "" {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(base, "cove")
}

func ConfigDir() string {
	return filepath.Dir(DefaultPath())
}

func (c *Config) Validate() error {
	if c.Options.TmpSize == "" {
		c.Options.TmpSize = "256m"
	}
	if c.Options.ProxyPort == 0 {
		c.Options.ProxyPort = 8080
	}
	if c.Options.ProxyPort < 1024 {
		return fmt.Errorf("proxy_port must be >=1024; the shim binds it after CAP_NET_BIND_SERVICE is dropped")
	}
	if err := validateCredMounts(c.Options.CredMount); err != nil {
		return err
	}
	if err := validateEnvPassthrough(c.Options.EnvPassthrough); err != nil {
		return err
	}

	allowSeen := map[string]string{}
	rules := make([]AllowRule, 0, len(c.Allow))
	for _, raw := range c.Allow {
		r, err := ParseRule(raw)
		if err != nil {
			return fmt.Errorf("allow %q: %w", raw, err)
		}
		key := ruleKey(r)
		if prev, ok := allowSeen[key]; ok {
			return fmt.Errorf("duplicate allow rules %q and %q", prev, raw)
		}
		allowSeen[key] = raw
		rules = append(rules, r)
	}
	c.AllowRules = rules

	injectSeen := map[string]string{}
	for i := range c.Inject {
		st := &c.Inject[i]
		r, err := ParseRule(st.Host)
		if err != nil {
			return fmt.Errorf("inject host %q: %w", st.Host, err)
		}
		st.Port = r.Port
		key := ruleKey(r)
		if prev, ok := injectSeen[key]; ok {
			return fmt.Errorf("duplicate inject hosts %q and %q", prev, st.Host)
		}
		injectSeen[key] = st.Host
		if prev, ok := allowSeen[key]; ok {
			return fmt.Errorf("host %q appears in both allow and inject (%q)", st.Host, prev)
		}
		if st.HeaderName == "" {
			return fmt.Errorf("inject %q missing header_name", st.Host)
		}
		if !strings.Contains(st.HeaderTemplate, "{secret}") {
			return fmt.Errorf("inject %q header_template must contain {secret}", st.Host)
		}
		if st.Secret == "" {
			return fmt.Errorf("inject %q missing secret", st.Host)
		}
		if !validSecretRef(st.Secret) {
			return fmt.Errorf("inject %q has unsupported secret ref %q", st.Host, st.Secret)
		}
		if st.DummyValue == "" {
			st.DummyValue = "cove-dummy-do-not-use"
		}
		if st.ALPN == "" {
			st.ALPN = "h2"
		}
		if st.ALPN != "h2" && st.ALPN != "http/1.1" {
			return fmt.Errorf("inject %q alpn must be h2 or http/1.1", st.Host)
		}
		if st.Mode != "" && st.Mode != "oauth-refresh" {
			return fmt.Errorf("inject %q mode %q not implemented in v0", st.Host, st.Mode)
		}
	}
	return nil
}

func ParseRule(raw string) (AllowRule, error) {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" {
		return AllowRule{}, errors.New("empty rule")
	}
	if raw == "*" {
		return AllowRule{}, errors.New("bare * is forbidden")
	}
	host, port, err := splitHostPortDefault(raw)
	if err != nil {
		return AllowRule{}, err
	}
	wild := false
	matchHost := host
	if strings.HasPrefix(host, "*.") {
		wild = true
		matchHost = strings.TrimPrefix(host, "*.")
		if matchHost == "" || strings.Contains(matchHost, "*") {
			return AllowRule{}, errors.New("wildcard must be a single leftmost label")
		}
	} else if strings.Contains(host, "*") {
		return AllowRule{}, errors.New("wildcard must be a single leftmost label")
	}
	if strings.Trim(host, ".") == "" {
		return AllowRule{}, errors.New("empty host")
	}
	return AllowRule{Pattern: raw, Host: matchHost, Wildcard: wild, Port: port}, nil
}

func splitHostPortDefault(raw string) (string, int, error) {
	host := raw
	port := 443
	if strings.HasPrefix(raw, "[") {
		h, p, err := net.SplitHostPort(raw)
		if err != nil {
			return "", 0, err
		}
		host = h
		n, err := strconv.Atoi(p)
		if err != nil || n <= 0 || n > 65535 {
			return "", 0, fmt.Errorf("invalid port %q", p)
		}
		return host, n, nil
	}
	if i := strings.LastIndex(raw, ":"); i >= 0 {
		p := raw[i+1:]
		if p != "" && allDigits(p) {
			host = raw[:i]
			n, err := strconv.Atoi(p)
			if err != nil || n <= 0 || n > 65535 {
				return "", 0, fmt.Errorf("invalid port %q", p)
			}
			port = n
		}
	}
	return host, port, nil
}

func allDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

func ruleKey(r AllowRule) string {
	prefix := "exact:"
	if r.Wildcard {
		prefix = "wild:"
	}
	return fmt.Sprintf("%s%s:%d", prefix, r.Host, r.Port)
}

func validSecretRef(ref string) bool {
	for _, p := range []string{"file:", "env:", "json:", "keyring:"} {
		if strings.HasPrefix(ref, p) && len(ref) > len(p) {
			return true
		}
	}
	return false
}

func validateCredMounts(entries []string) error {
	for _, e := range entries {
		path, mode := e, ""
		if strings.HasSuffix(e, ":rw") {
			path = strings.TrimSuffix(e, ":rw")
			mode = "rw"
		} else if strings.Contains(e, ":") {
			return fmt.Errorf("cred_mount %q has unsupported suffix; use PATH or PATH:rw", e)
		}
		if mode == "rw" && path == "" {
			return fmt.Errorf("cred_mount %q missing path", e)
		}
		clean := filepath.Clean(path)
		if path == "" || path == "*" || clean == "." || clean == "~" || clean == "/" || strings.Contains(path, "*") {
			return fmt.Errorf("cred_mount %q is too broad", e)
		}
	}
	return nil
}

func validateEnvPassthrough(entries []string) error {
	for _, e := range entries {
		if e == "" || e == "*" {
			return fmt.Errorf("env_passthrough %q is too broad", e)
		}
		if strings.Contains(e, "*") && !strings.HasSuffix(e, "*") {
			return fmt.Errorf("env_passthrough %q may only use a single trailing *", e)
		}
		if strings.Count(e, "*") > 1 {
			return fmt.Errorf("env_passthrough %q may only use a single trailing *", e)
		}
		if e == "~" || e == "/" {
			return fmt.Errorf("env_passthrough %q is invalid", e)
		}
	}
	return nil
}
