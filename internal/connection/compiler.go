package connection

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"cove/internal/config"
	"cove/internal/secret"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// Plan is deliberately value-only: it describes policy and secret file names,
// never a secret value. Compile performs no I/O beyond its supplied snapshot.
type Plan struct {
	Name       string
	Stanza     config.InjectStanza
	BlockBase  bool
	SecretPath string
	Try        string
}

// MTLSPlan is deliberately reference-only. Client identity material remains at
// the user-selected host paths; cove neither copies it nor puts it in output.
type MTLSPlan struct {
	Name      string
	Stanza    config.MTLSStanza
	BlockBase []config.PolicyRef
}

const s3MaxBodyBytes int64 = 67108864

// S3Plan only contains policy metadata. AWS credential values remain inside
// the SDK provider on the host and are never written to cove state.
type S3Plan struct {
	Name      string
	Stanza    config.SigV4Stanza
	BlockBase []config.PolicyRef
	Verified  bool
}

var loadAWSProfile = secret.AWSProfile
var inferAWSAccount = func(ctx context.Context, cfg aws.Config) (string, error) {
	out, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil || out.Account == nil {
		return "", err
	}
	return *out.Account, nil
}

func compileS3(uri, profile, region, account string, readWrite, deleteObjects bool, cfg *config.Config) (S3Plan, error) {
	bucket, prefix, err := parseS3URI(uri)
	if err != nil {
		return S3Plan{}, err
	}
	if deleteObjects && !readWrite {
		return S3Plan{}, errors.New("--delete requires --read-write")
	}
	if profile == "" {
		profile = "default"
	}
	var awsCfg aws.Config
	if region == "" {
		awsCfg, err = loadAWSProfile(context.Background(), profile)
		if err != nil {
			// Region precedence is --region, then the profile's region. If the
			// profile cannot be loaded to infer one, guide the user to --region
			// rather than surfacing a raw SDK error.
			return S3Plan{}, fmt.Errorf("could not determine AWS region from profile %q; rerun with --region REGION: %w", profile, err)
		}
		region = awsCfg.Region
	}
	if region == "" {
		return S3Plan{}, errors.New("AWS region is required; rerun with --region REGION")
	}
	verified := account == ""
	if account == "" {
		if awsCfg.Region == "" { // --region supplied; still load provider for signed STS.
			awsCfg, err = loadAWSProfile(context.Background(), profile)
			if err != nil {
				return S3Plan{}, fmt.Errorf("cannot load AWS profile %q: %w", profile, err)
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		account, err = inferAWSAccount(ctx, awsCfg)
		if err != nil || !regexp.MustCompile(`^[0-9]{12}$`).MatchString(account) {
			return S3Plan{}, fmt.Errorf("could not infer AWS account; rerun with --account 123456789012: %w", err)
		}
	}
	if !regexp.MustCompile(`^[0-9]{12}$`).MatchString(account) {
		return S3Plan{}, errors.New("--account must be a 12-digit AWS account ID")
	}
	host := bucket + ".s3." + region + ".amazonaws.com"
	methods := []string{"GET", "HEAD"}
	ops := []string{"s3:GetObject", "s3:HeadObject", "s3:ListBucket"}
	if readWrite {
		methods = append(methods, "PUT")
		ops = append(ops, "s3:PutObject", "s3:CopyObject")
	}
	if deleteObjects {
		methods = append(methods, "DELETE")
		ops = append(ops, "s3:DeleteObject")
	}
	resources := []string{"arn:aws:s3:::" + bucket, "arn:aws:s3:::" + bucket + "/" + prefix + "*"}
	p := S3Plan{Name: "s3-" + bucket, Verified: verified, Stanza: config.SigV4Stanza{Name: "s3-" + bucket, Host: host, Profile: profile, AccountID: account, Service: "s3", Region: region, AllowedMethods: methods, AllowedOperations: ops, AllowedResources: resources, MaxBodyBytes: s3MaxBodyBytes}}
	for _, st := range cfg.SigV4 {
		if samePolicyHost(st.Host, host) && st.Name != "" && st.Name != p.Name {
			return S3Plan{}, fmt.Errorf("%s is already owned by %s", host, st.Name)
		}
		if samePolicyHost(st.Host, host) && st.Name == "" {
			p.BlockBase = append(p.BlockBase, config.PolicyRef{Kind: "sigv4", Host: host})
		}
	}
	for _, st := range cfg.Inject {
		if samePolicyHost(st.Host, host) {
			return S3Plan{}, fmt.Errorf("%s is already owned by %s", host, policyName(st.Name, "inject"))
		}
	}
	for _, a := range cfg.AllowRules {
		if sameRule(a, mustExactRule(host)) {
			p.BlockBase = append(p.BlockBase, config.PolicyRef{Kind: "allow", Host: host})
		}
	}
	return p, nil
}

func mustExactRule(host string) config.AllowRule { r, _ := config.ParseExactRule(host); return r }

func parseS3URI(raw string) (bucket, prefix string, err error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "s3" || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return "", "", errors.New("S3 URI must be s3://BUCKET/PREFIX/")
	}
	if !strings.HasSuffix(u.Path, "/") {
		return "", "", errors.New("S3 URI prefix must end in / to avoid empty-prefix ambiguity")
	}
	if strings.ContainsAny(u.Path, "\\*") || strings.Contains(strings.ToLower(u.EscapedPath()), "%2f") || strings.Contains(strings.ToLower(u.EscapedPath()), "%5c") {
		return "", "", errors.New("S3 URI contains an unsupported separator or wildcard")
	}
	for _, part := range strings.Split(strings.Trim(u.Path, "/"), "/") {
		if part == "." || part == ".." {
			return "", "", errors.New("S3 URI contains dot segments")
		}
	}
	// Config is the authority for bucket grammar; a temporary valid stanza keeps
	// this parser from inventing a looser second grammar.
	if _, err := config.LoadBytes([]byte("[[sigv4]]\nhost = \"" + u.Host + ".s3.us-east-1.amazonaws.com\"\nprofile = \"default\"\naccount_id = \"000000000000\"\nservice = \"s3\"\nregion = \"us-east-1\"\nallowed_methods=[\"GET\",\"HEAD\"]\nallowed_operations=[\"s3:GetObject\",\"s3:HeadObject\",\"s3:ListBucket\"]\nallowed_resources=[\"arn:aws:s3:::" + u.Host + "\",\"arn:aws:s3:::" + u.Host + "/*\"]\nmax_body_bytes=1\n")); err != nil {
		return "", "", errors.New("invalid S3 bucket")
	}
	return u.Host, strings.TrimPrefix(u.EscapedPath(), "/"), nil
}

func commitS3Plan(ctx context.Context, p S3Plan) error {
	return commitManaged(ctx, func(m *config.ManagedConfig) error {
		for _, b := range p.BlockBase {
			found := false
			for _, x := range m.Block {
				if x == b {
					found = true
				}
			}
			if !found {
				m.Block = append(m.Block, b)
			}
		}
		for i := range m.SigV4 {
			if m.SigV4[i].Name == p.Name {
				m.SigV4[i] = p.Stanza
				return nil
			}
		}
		m.SigV4 = append(m.SigV4, p.Stanza)
		return nil
	})
}

func previewS3Plan(p S3Plan) string {
	verified := "STS-verified"
	if !p.Verified {
		verified = "not STS-verified"
	}
	return fmt.Sprintf("protected: S3 SigV4\nhost: %s:443\naccount: %s (%s)\nprofile: %s (credentials remain host-side; absent from the box)\noperations: %s\nmax body: %d bytes\nresidual: cove signs only after policy checks\n", p.Stanza.Host, p.Stanza.AccountID, verified, p.Stanza.Profile, strings.Join(p.Stanza.AllowedOperations, ", "), p.Stanza.MaxBodyBytes)
}

// commitManaged applies a complete policy transition in one managed-config
// replacement.  It is used for multi-host connections (notably GitHub), where
// observing half a transition would be unsafe.
func commitManaged(ctx context.Context, mutate func(*config.ManagedConfig) error) error {
	return config.EditManagedConfig(ctx, func(m *config.ManagedConfig) error {
		m.Version = 1
		return mutate(m)
	})
}

func compileService(s Service, cfg *config.Config) (Plan, error) {
	st := s.Stanza
	st.Secret = "file:" + filepath.Join(config.ConfigDir(), "secrets", s.SecretFile)
	p := Plan{Name: s.Name, Stanza: st, SecretPath: strings.TrimPrefix(st.Secret, "file:"), Try: s.Try}
	for _, current := range cfg.Inject {
		if current.Host == st.Host && current.Name != "" && current.Name != st.Name {
			return Plan{}, fmt.Errorf("%s is already owned by %s", st.Host, current.Name)
		}
		if current.Host == st.Host && current.Name == "" {
			p.BlockBase = true
		}
	}
	return p, nil
}

func commitPlan(ctx context.Context, p Plan, secret []byte) error {
	// Secret first means a crash can leave only an unused host-side credential.
	if err := config.WriteSecretAtomic(p.SecretPath, secret); err != nil {
		return err
	}
	return commitManaged(ctx, func(m *config.ManagedConfig) error {
		if p.BlockBase {
			found := false
			for _, b := range m.Block {
				if b.Kind == "inject" && b.Host == p.Stanza.Host {
					found = true
				}
			}
			if !found {
				m.Block = append(m.Block, config.PolicyRef{Kind: "inject", Host: p.Stanza.Host})
			}
		}
		for i := range m.Inject {
			if m.Inject[i].Name == p.Name {
				m.Inject[i] = p.Stanza
				return nil
			}
		}
		m.Inject = append(m.Inject, p.Stanza)
		return nil
	})
}

func previewPlan(p Plan) string {
	return fmt.Sprintf("protected: %s\nhost: %s:443\ncredential: stored host-side at %s; absent from the box\nresidual: cove stamps the credential only after policy checks\n%s\n", p.Name, p.Stanza.Host, p.SecretPath, p.Try)
}

func compileMTLS(host, certPath, keyPath string, rules []config.MTLSRule, cfg *config.Config) (MTLSPlan, error) {
	rule, err := config.ParseExactRule(host)
	if err != nil {
		return MTLSPlan{}, fmt.Errorf("invalid mTLS host: %w", err)
	}
	canonical := config.FormatExactRule(rule)
	certPath, err = filepath.Abs(certPath)
	if err != nil {
		return MTLSPlan{}, fmt.Errorf("certificate path: %w", err)
	}
	keyPath, err = filepath.Abs(keyPath)
	if err != nil {
		return MTLSPlan{}, fmt.Errorf("key path: %w", err)
	}
	if err := preflightMTLSIdentity(certPath, keyPath); err != nil {
		return MTLSPlan{}, err
	}
	name := mtlsName(canonical)
	p := MTLSPlan{Name: name, Stanza: config.MTLSStanza{
		Name: name, Host: canonical, ClientCert: "file:" + certPath, ClientKey: "file:" + keyPath, Rules: rules,
	}}

	// A managed mTLS policy may replace its own earlier revision. Any other
	// generated policy owns the host and must be removed explicitly first.
	for _, st := range cfg.Inject {
		if samePolicyHost(st.Host, canonical) {
			return MTLSPlan{}, fmt.Errorf("%s is already owned by %s", canonical, policyName(st.Name, "inject"))
		}
	}
	for _, st := range cfg.SigV4 {
		if samePolicyHost(st.Host, canonical) {
			return MTLSPlan{}, fmt.Errorf("%s is already owned by %s", canonical, policyName(st.Name, "sigv4"))
		}
	}
	for _, allow := range cfg.AllowRules {
		if sameRule(allow, rule) {
			if managedAllowForHost(cfg, canonical) {
				return MTLSPlan{}, fmt.Errorf("%s is already owned by a managed allow policy", canonical)
			}
			p.BlockBase = append(p.BlockBase, config.PolicyRef{Kind: "allow", Host: canonical})
		}
	}
	for _, st := range cfg.MTLS {
		if !samePolicyHost(st.Host, canonical) {
			continue
		}
		if st.Name != "" && st.Name != name {
			return MTLSPlan{}, fmt.Errorf("%s is already owned by %s", canonical, st.Name)
		}
		if st.Name == "" {
			p.BlockBase = append(p.BlockBase, config.PolicyRef{Kind: "mtls", Host: canonical})
		}
	}
	return p, nil
}

func managedAllowForHost(cfg *config.Config, host string) bool {
	for _, allow := range cfg.Managed.Allow {
		if samePolicyHost(allow.Host, host) {
			return true
		}
	}
	return false
}

func mtlsName(host string) string { return "mtls-" + strings.ReplaceAll(host, ":", "-") }

func policyName(name, kind string) string {
	if name != "" {
		return name
	}
	return "manual " + kind + " policy"
}

func samePolicyHost(host, canonical string) bool {
	r, err := config.ParseExactRule(host)
	return err == nil && config.FormatExactRule(r) == canonical
}

// preflightMTLSIdentity deliberately reads only host-side files. A pairing
// failure never reaches the managed editor, and therefore cannot enable a
// policy with unavailable identity material.
func preflightMTLSIdentity(certPath, keyPath string) error {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("certificate file is missing")
		}
		return fmt.Errorf("cannot read certificate file: %w", err)
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("key file is missing")
		}
		return fmt.Errorf("cannot stat key file: %w", err)
	}
	if info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("key file must not be group- or world-readable")
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("cannot read key file: %w", err)
	}
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return fmt.Errorf("certificate and key are not a valid PEM pair")
	}
	return nil
}

func commitMTLSPlan(ctx context.Context, p MTLSPlan) error {
	return commitManaged(ctx, func(m *config.ManagedConfig) error {
		for _, block := range p.BlockBase {
			found := false
			for _, current := range m.Block {
				if current == block {
					found = true
				}
			}
			if !found {
				m.Block = append(m.Block, block)
			}
		}
		for i := range m.MTLS {
			if m.MTLS[i].Name == p.Name {
				m.MTLS[i] = p.Stanza
				return nil
			}
		}
		m.MTLS = append(m.MTLS, p.Stanza)
		return nil
	})
}

func previewMTLSPlan(p MTLSPlan) string {
	var b strings.Builder
	fmt.Fprintf(&b, "protected: mTLS\nhost: %s\nclient certificate: stored host-side; absent from the box\nallowed pairs:\n", p.Stanza.Host)
	for _, rule := range p.Stanza.Rules {
		fmt.Fprintf(&b, "  %s %s\n", rule.Method, rule.PathPrefix)
	}
	b.WriteString("residual: cove presents the client certificate only after the configured method/path pair passes policy checks\n")
	return b.String()
}
