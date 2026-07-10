package config

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"cove/internal/clierr"
	"github.com/BurntSushi/toml"
)

// Diagnostic is reserved for document-aware validation diagnostics.
type Diagnostic struct {
	Location *clierr.Location
	Message  string
}

// ValidationError preserves the logical TOML target for cross-field checks,
// where the decoder itself has no single token to report.
type ValidationError struct {
	KeyPath  string
	Kind     string
	Identity string
	Cause    error
}

func (e *ValidationError) Error() string { return e.Cause.Error() }
func (e *ValidationError) Unwrap() error { return e.Cause }

// Document keeps the original source alongside the decoded effective config.
type Document struct {
	Path        string
	Bytes       []byte
	Meta        toml.MetaData
	Raw         any
	Config      *Config
	Diagnostics []Diagnostic
}

// DecodeDocument decodes and validates one complete TOML document.
func DecodeDocument(path string, data []byte) (*Document, error) {
	raw := rawConfig{Options: rawOptions{Options: Options{TmpSize: "256m", ProxyPort: 8080, Audit: true}}}
	meta, err := toml.Decode(string(data), &raw)
	if err != nil {
		var pe toml.ParseError
		if errors.As(err, &pe) {
			return nil, clierr.Wrap(clierr.EXConfig, "could not load the policy", &clierr.Location{Path: path, Line: pe.Position.Line, Column: pe.Position.Col, Detail: pe.Message}, "cove config edit", err)
		}
		return nil, clierr.Wrap(clierr.EXConfig, "could not load the policy", decodeLocation(path, data, err), "cove config edit", err)
	}
	for _, key := range meta.Undecoded() {
		parts := key.String()
		if parts == "managed" || strings.HasPrefix(parts, "managed.") {
			return nil, clierr.Wrap(clierr.EXConfig, "could not load the policy", nil, "cove config edit", fmt.Errorf("unknown key %q in managed block", parts))
		}
	}
	cfg, err := compileRaw(raw)
	if err != nil {
		verr := validationError(data, err)
		return nil, clierr.Wrap(clierr.EXConfig, "could not load the policy", semanticLocation(path, data, verr), "cove config edit", verr)
	}
	if err := cfg.Validate(); err != nil {
		verr := validationError(data, err)
		return nil, clierr.Wrap(clierr.EXConfig, "could not load the policy", semanticLocation(path, data, verr), "cove config edit", verr)
	}
	return &Document{Path: path, Bytes: append([]byte(nil), data...), Meta: meta, Raw: raw, Config: cfg}, nil
}

func validationError(data []byte, cause error) *ValidationError {
	v := &ValidationError{Cause: cause}
	if strings.Contains(cause.Error(), "appears in both") {
		v.KeyPath = "host"
		for _, sourceLine := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimSpace(sourceLine)
			if strings.HasPrefix(trimmed, "[[") && strings.HasSuffix(trimmed, "]]") {
				v.Kind = strings.TrimSuffix(strings.TrimPrefix(trimmed, "[["), "]]")
			}
			if strings.HasPrefix(trimmed, "host") {
				v.Identity = strings.TrimSpace(strings.TrimPrefix(trimmed, "host ="))
			}
		}
	}
	return v
}

func configFromRaw(raw rawConfig) *Config {
	cfg := &Config{Options: raw.Options.Options, Allow: raw.Allow, Inject: raw.Inject, SigV4: raw.SigV4, MTLS: raw.MTLS}
	if len(cfg.Allow) == 0 && len(raw.Options.Allow) > 0 {
		cfg.Allow = raw.Options.Allow
	}
	return cfg
}

// compileRaw removes only explicitly named base policies, then appends the
// cove-owned policies. Validation is deliberately performed by the caller on
// this flat result so the matcher has exactly the same input shape as before.
func compileRaw(raw rawConfig) (*Config, error) {
	base := configFromRaw(raw)
	m := raw.Managed
	if m.Version == 0 && len(m.Allow)+len(m.Block)+len(m.Inject)+len(m.SigV4)+len(m.MTLS) == 0 {
		return base, nil
	}
	if m.Version != 1 {
		return nil, fmt.Errorf("managed version %d is not supported", m.Version)
	}
	seenNames := map[string]bool{}
	name := func(n string) error {
		if n == "" {
			return fmt.Errorf("managed policy missing name")
		}
		if seenNames[n] {
			return fmt.Errorf("duplicate managed policy name %q", n)
		}
		seenNames[n] = true
		return nil
	}
	for _, x := range m.Allow {
		if err := name(x.Name); err != nil {
			return nil, err
		}
	}
	for _, x := range m.Inject {
		if err := name(x.Name); err != nil {
			return nil, err
		}
	}
	for _, x := range m.SigV4 {
		if err := name(x.Name); err != nil {
			return nil, err
		}
	}
	for _, x := range m.MTLS {
		if err := name(x.Name); err != nil {
			return nil, err
		}
	}
	blocks := map[string]bool{}
	for _, b := range m.Block {
		if b.Kind != "allow" && b.Kind != "inject" && b.Kind != "sigv4" && b.Kind != "mtls" {
			return nil, fmt.Errorf("managed block has invalid kind %q", b.Kind)
		}
		r, err := ParseRule(b.Host)
		if err != nil {
			return nil, fmt.Errorf("managed block host %q: %w", b.Host, err)
		}
		key := b.Kind + ":" + ruleKey(r)
		if blocks[key] {
			return nil, fmt.Errorf("duplicate managed block %q", key)
		}
		blocks[key] = true
	}
	filter := func(kind string, hosts []string) ([]string, error) {
		out := make([]string, 0, len(hosts))
		found := map[string]bool{}
		for _, h := range hosts {
			r, err := ParseRule(h)
			if err != nil {
				return nil, err
			}
			k := kind + ":" + ruleKey(r)
			if blocks[k] {
				found[k] = true
				continue
			}
			out = append(out, h)
		}
		for k := range blocks {
			if strings.HasPrefix(k, kind+":") && !found[k] {
				return nil, fmt.Errorf("managed block %q does not match a base policy", k)
			}
		}
		return out, nil
	}
	var err error
	if base.Allow, err = filter("allow", base.Allow); err != nil {
		return nil, err
	}
	filterStanzas := func(kind string, in []InjectStanza) ([]InjectStanza, error) {
		out := make([]InjectStanza, 0, len(in))
		found := map[string]bool{}
		for _, s := range in {
			r, e := ParseRule(s.Host)
			if e != nil {
				return nil, e
			}
			k := kind + ":" + ruleKey(r)
			if blocks[k] {
				found[k] = true
				continue
			}
			out = append(out, s)
		}
		for k := range blocks {
			if strings.HasPrefix(k, kind+":") && !found[k] {
				return nil, fmt.Errorf("managed block %q does not match a base policy", k)
			}
		}
		return out, nil
	}
	if base.Inject, err = filterStanzas("inject", base.Inject); err != nil {
		return nil, err
	}
	filterSig := func(in []SigV4Stanza) ([]SigV4Stanza, error) {
		out := make([]SigV4Stanza, 0, len(in))
		found := map[string]bool{}
		for _, s := range in {
			r, e := ParseRule(s.Host)
			if e != nil {
				return nil, e
			}
			k := "sigv4:" + ruleKey(r)
			if blocks[k] {
				found[k] = true
				continue
			}
			out = append(out, s)
		}
		for k := range blocks {
			if strings.HasPrefix(k, "sigv4:") && !found[k] {
				return nil, fmt.Errorf("managed block %q does not match a base policy", k)
			}
		}
		return out, nil
	}
	if base.SigV4, err = filterSig(base.SigV4); err != nil {
		return nil, err
	}
	filterMTLS := func(in []MTLSStanza) ([]MTLSStanza, error) {
		out := make([]MTLSStanza, 0, len(in))
		found := map[string]bool{}
		for _, s := range in {
			r, e := ParseRule(s.Host)
			if e != nil {
				return nil, e
			}
			k := "mtls:" + ruleKey(r)
			if blocks[k] {
				found[k] = true
				continue
			}
			out = append(out, s)
		}
		for k := range blocks {
			if strings.HasPrefix(k, "mtls:") && !found[k] {
				return nil, fmt.Errorf("managed block %q does not match a base policy", k)
			}
		}
		return out, nil
	}
	if base.MTLS, err = filterMTLS(base.MTLS); err != nil {
		return nil, err
	}
	for _, a := range m.Allow {
		base.Allow = append(base.Allow, a.Host)
	}
	base.Inject = append(base.Inject, m.Inject...)
	base.SigV4 = append(base.SigV4, m.SigV4...)
	base.MTLS = append(base.MTLS, m.MTLS...)
	base.Managed = ManagedConfig{Version: m.Version, Allow: m.Allow, Block: m.Block, Inject: m.Inject, SigV4: m.SigV4, MTLS: m.MTLS}
	return base, nil
}

// semanticLocation uses TOML's already-decoded document only for presentation.
// When a field cannot be identified, it cites the relevant table header.
func semanticLocation(path string, data []byte, err error) *clierr.Location {
	text := string(data)
	line, col := 0, 0
	legacyKey := ""
	if strings.Contains(err.Error(), "allowed_methods is no longer supported") {
		legacyKey = "allowed_methods"
	} else if strings.Contains(err.Error(), "allowed_path_prefixes is no longer supported") {
		legacyKey = "allowed_path_prefixes"
	}
	if legacyKey != "" {
		inMTLS := false
		for i, sourceLine := range strings.Split(text, "\n") {
			trimmed := strings.TrimSpace(sourceLine)
			if strings.HasPrefix(trimmed, "[[") && strings.HasSuffix(trimmed, "]]") {
				table := strings.TrimSuffix(strings.TrimPrefix(trimmed, "[["), "]]")
				inMTLS = table == "mtls" || table == "managed.mtls"
			}
			if inMTLS && strings.HasPrefix(trimmed, legacyKey) && strings.Contains(trimmed, "=") {
				return &clierr.Location{Path: path, Line: i + 1, Column: 1, Detail: err.Error()}
			}
		}
	}
	for i, s := range strings.Split(text, "\n") {
		if strings.HasPrefix(strings.TrimSpace(s), "[[") || strings.HasPrefix(strings.TrimSpace(s), "[") {
			line, col = i+1, 1
		}
	}
	// Host conflicts are most useful at the second policy's host key.
	if strings.Contains(err.Error(), "appears in both") {
		for i, sourceLine := range strings.Split(text, "\n") {
			if strings.HasPrefix(strings.TrimSpace(sourceLine), "host") {
				line, col = i+1, 1
			}
		}
	}
	return &clierr.Location{Path: path, Line: line, Column: col, Detail: err.Error()}
}

func decodeLocation(path string, data []byte, err error) *clierr.Location {
	// BurntSushi reports structural conversion errors without a ParseError.
	// The document scan is display-only and deliberately leaves TOML semantics
	// to the decoder above.
	re := regexp.MustCompile(`(?m)^[ \t]*[A-Za-z0-9_-]+[ \t]*=`)
	if matches := re.FindAllIndex(data, -1); len(matches) > 0 {
		line, col := lineAt(string(data), matches[len(matches)-1][0])
		return &clierr.Location{Path: path, Line: line, Column: col, Detail: err.Error()}
	}
	return nil
}

func lineAt(text string, offset int) (line, col int) {
	line, col = 1, 1
	for i, r := range text {
		if i >= offset {
			break
		}
		if r == '\n' {
			line, col = line+1, 1
		} else {
			col++
		}
	}
	return line, col
}

func (d *Document) String() string { return fmt.Sprintf("%s", d.Path) }
