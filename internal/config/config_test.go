package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cove/internal/clierr"
)

func TestSeedValidates(t *testing.T) {
	cfg, err := LoadBytes([]byte(DefaultConfig))
	if err != nil {
		t.Fatalf("seed config did not validate: %v", err)
	}
	if len(cfg.AllowRules) == 0 {
		t.Fatalf("seed allow rules were not compiled")
	}
}

func TestShippedDefaultConfigAndGitHubPATMigrationValidate(t *testing.T) {
	seed, err := os.ReadFile("default_config.toml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBytes(seed); err != nil {
		t.Fatalf("shipped default_config.toml did not validate: %v", err)
	}

	// The documented migration removes the OAuth allow rules and uncommenting
	// both examples creates the exact GitHub API + smart-HTTP policy pair.
	migrated := string(seed)
	migrated = strings.Replace(migrated, `  "github.com", "api.github.com", "codeload.github.com", "*.githubusercontent.com",`, `  "codeload.github.com", "*.githubusercontent.com",`, 1)
	for _, line := range []string{
		"# [[inject]]", "# host =", "# header_name =", "# header_template =", "# secret =", "# dummy_env =", "# transform =", "# basic_username =", "# github_repositories =", "# allowed_methods =",
	} {
		migrated = strings.ReplaceAll(migrated, line, strings.TrimPrefix(line, "# "))
	}
	if _, err := LoadBytes([]byte(migrated)); err != nil {
		t.Fatalf("GitHub PAT migration did not validate: %v", err)
	}
}

func TestValidateRejectsBareWildcard(t *testing.T) {
	_, err := LoadBytes([]byte(`allow = ["*"]`))
	if err == nil {
		t.Fatalf("expected bare wildcard rejection")
	}
}

func TestValidateRejectsConflict(t *testing.T) {
	_, err := LoadBytes([]byte(`
allow = ["github.com"]
[[inject]]
host = "github.com"
header_name = "Authorization"
header_template = "Bearer {secret}"
secret = "env:TOKEN"
`))
	if err == nil {
		t.Fatalf("expected allow/inject conflict")
	}
}

func TestParseWildcard(t *testing.T) {
	r, err := ParseRule("*.githubusercontent.com")
	if err != nil {
		t.Fatal(err)
	}
	if !r.Wildcard || r.Host != "githubusercontent.com" || r.Port != 443 {
		t.Fatalf("bad wildcard parse: %+v", r)
	}
}

func TestValidateRejectsHeaderTemplateWithoutSecret(t *testing.T) {
	_, err := LoadBytes([]byte(`
[[inject]]
host = "api.example.com"
header_name = "Authorization"
header_template = "Bearer token"
secret = "env:TOKEN"
`))
	if err == nil {
		t.Fatalf("expected header_template without {secret} to be rejected")
	}
}

func TestValidateRejectsBroadCredMountAndEnvPassthrough(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"cred star", `[options]` + "\n" + `cred_mount = ["*"]`},
		{"cred tilde", `[options]` + "\n" + `cred_mount = ["~"]`},
		{"cred tilde slash", `[options]` + "\n" + `cred_mount = ["~/"]`},
		{"cred root", `[options]` + "\n" + `cred_mount = ["/"]`},
		{"cred dot", `[options]` + "\n" + `cred_mount = ["."]`},
		{"cred glob", `[options]` + "\n" + `cred_mount = ["~/.config/*"]`},
		{"cred bad suffix", `[options]` + "\n" + `cred_mount = ["~/.codex:ro"]`},
		{"runtime star", `[options]` + "\n" + `runtime_mount = ["*"]`},
		{"runtime tilde", `[options]` + "\n" + `runtime_mount = ["~"]`},
		{"runtime tilde slash", `[options]` + "\n" + `runtime_mount = ["~/"]`},
		{"runtime root", `[options]` + "\n" + `runtime_mount = ["/"]`},
		{"runtime home root", `[options]` + "\n" + `runtime_mount = ["/home"]`},
		{"runtime slash root", `[options]` + "\n" + `runtime_mount = ["/root"]`},
		{"runtime etc", `[options]` + "\n" + `runtime_mount = ["/etc"]`},
		{"runtime parent", `[options]` + "\n" + `runtime_mount = [".."]`},
		{"runtime glob", `[options]` + "\n" + `runtime_mount = ["~/.nvm/*"]`},
		{"runtime rw suffix", `[options]` + "\n" + `runtime_mount = ["~/.nvm:rw"]`},
		{"env star", `[options]` + "\n" + `env_passthrough = ["*"]`},
		{"env tilde", `[options]` + "\n" + `env_passthrough = ["~"]`},
		{"env root", `[options]` + "\n" + `env_passthrough = ["/"]`},
		{"env empty", `[options]` + "\n" + `env_passthrough = [""]`},
		{"env middle glob", `[options]` + "\n" + `env_passthrough = ["AWS_*_KEY"]`},
		{"env double glob", `[options]` + "\n" + `env_passthrough = ["AWS_**"]`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := LoadBytes([]byte(tt.body)); err == nil {
				t.Fatalf("expected rejection")
			}
		})
	}
}

func TestValidateRejectsRuntimeMountHomeOrAncestor(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	for _, path := range []string{home, filepath.Dir(home)} {
		t.Run(path, func(t *testing.T) {
			if _, err := LoadBytes([]byte(`[options]` + "\n" + `runtime_mount = ["` + path + `"]`)); err == nil {
				t.Fatalf("expected runtime_mount HOME-or-above rejection for %q", path)
			}
		})
	}
}

func TestValidateAcceptsEnvPassthroughTrailingGlobAndCredRWSuffix(t *testing.T) {
	cfg, err := LoadBytes([]byte(`
[options]
cred_mount = ["~/.codex:rw"]
runtime_mount = ["~/.nvm/versions/node/v22.0.0"]
env_passthrough = ["AWS_*", "EXACT_TOKEN"]
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Options.CredMount) != 1 || len(cfg.Options.RuntimeMount) != 1 || len(cfg.Options.EnvPassthrough) != 2 {
		t.Fatalf("options not retained: %+v", cfg.Options)
	}
}

func TestValidateRejectsInvalidWildcardRulesAndPorts(t *testing.T) {
	for _, body := range []string{
		`allow = ["api.*.example.com"]`,
		`allow = ["*."]`,
		`allow = ["example.com:0"]`,
		`allow = ["example.com:70000"]`,
	} {
		t.Run(body, func(t *testing.T) {
			if _, err := LoadBytes([]byte(body)); err == nil {
				t.Fatalf("expected rejection")
			}
		})
	}
}

func TestParseRuleIPLiteralAndHostPort(t *testing.T) {
	tests := []struct {
		raw  string
		host string
		port int
	}{
		{"1.2.3.4", "1.2.3.4", 443},
		{"1.2.3.4:8443", "1.2.3.4", 8443},
		{"github.com:9443", "github.com", 9443},
		{"[2001:db8::1]:443", "2001:db8::1", 443},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			r, err := ParseRule(tt.raw)
			if err != nil {
				t.Fatal(err)
			}
			if r.Host != tt.host || r.Port != tt.port {
				t.Fatalf("ParseRule(%q) = host %q port %d, want %q %d", tt.raw, r.Host, r.Port, tt.host, tt.port)
			}
		})
	}
}

func TestMissingSecretFileInjectStanzaIsInertAtConfigLoad(t *testing.T) {
	cfg, err := LoadBytes([]byte(`
[[inject]]
host = "api.example.com"
header_name = "Authorization"
header_template = "Bearer {secret}"
secret = "file:/definitely/missing/cove/test/secret"
`))
	if err != nil {
		t.Fatalf("missing secret file should not reject config: %v", err)
	}
	if len(cfg.Inject) != 1 {
		t.Fatalf("inject len = %d, want 1", len(cfg.Inject))
	}
}

func TestPolicyClaimsAreExclusiveAcrossKinds(t *testing.T) {
	host := "s3.us-east-1.amazonaws.com"
	stanzas := map[string]string{
		"allow": `allow = ["` + host + `"]`,
		"inject": `[[inject]]
host="` + host + `"
header_name="Authorization"
header_template="Bearer {secret}"
secret="env:TOKEN"`,
		"sigv4": validSigV4(host),
		"mtls":  validMTLS(host),
	}
	for left, leftConfig := range stanzas {
		for right, rightConfig := range stanzas {
			if left >= right {
				continue
			}
			t.Run(left+"/"+right, func(t *testing.T) {
				if _, err := LoadBytes([]byte(leftConfig + "\n" + rightConfig)); err == nil || !strings.Contains(err.Error(), "appears in both") {
					t.Fatalf("same host %s/%s should conflict, got %v", left, right, err)
				}
			})
		}
	}
}

func TestSpecializedStanzasDecode(t *testing.T) {
	cfg, err := LoadBytes([]byte(validSigV4("my-bucket.s3.us-east-1.amazonaws.com") + "\n" + validMTLS("partner.example.com")))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.SigV4) != 1 || len(cfg.MTLS) != 1 {
		t.Fatalf("specialized TOML stanzas were dropped: %+v", cfg)
	}
}

func TestSigV4EndpointAndResourceValidation(t *testing.T) {
	validHosts := []string{"s3.amazonaws.com", "s3.us-east-1.amazonaws.com", "my-bucket.s3.us-east-1.amazonaws.com", "*.s3.us-east-1.amazonaws.com"}
	for _, host := range validHosts {
		t.Run("accept/"+host, func(t *testing.T) {
			if _, err := LoadBytes([]byte(validSigV4(host))); err != nil {
				t.Fatal(err)
			}
		})
	}
	invalidHosts := []struct{ host, region string }{
		{"s3-accelerate.amazonaws.com", "us-east-1"},
		{"s3.dualstack.us-east-1.amazonaws.com", "us-east-1"},
		{"bucket.s3.dualstack.us-east-1.amazonaws.com", "us-east-1"},
		{"s3-fips.us-east-1.amazonaws.com", "us-east-1"},
		{"bucket.s3-accesspoint.us-east-1.amazonaws.com", "us-east-1"},
		{"bucket.s3-outposts.us-east-1.amazonaws.com", "us-east-1"},
		{"name.mrap.accesspoint.s3-global.amazonaws.com", "us-east-1"},
		{"s3-control.us-east-1.amazonaws.com", "us-east-1"},
		{"s3.cn-north-1.amazonaws.com.cn", "cn-north-1"},
		{"s3.cn-north-1.amazonaws.com", "cn-north-1"},
		{"s3.us-gov-west-1.amazonaws.com", "us-gov-west-1"},
		{"s3.us-iso-east-1.amazonaws.com", "us-iso-east-1"},
		{"s3.us-isob-east-1.amazonaws.com", "us-isob-east-1"},
		{"s3.example.com", "us-east-1"},
		{"*.amazonaws.com", "us-east-1"},
	}
	for _, tt := range invalidHosts {
		t.Run("reject/"+tt.host, func(t *testing.T) {
			body := strings.Replace(validSigV4(tt.host), `region="us-east-1"`, `region="`+tt.region+`"`, 1)
			if _, err := LoadBytes([]byte(body)); err == nil {
				t.Fatal("expected endpoint rejection")
			}
		})
	}
	for _, resource := range []string{"arn:aws:s3:::my-bucket/*", "arn:aws:s3:::my-bucket/a/b", "arn:aws:s3:::my-bucket"} {
		t.Run("resource/"+resource, func(t *testing.T) {
			body := strings.Replace(validSigV4("my-bucket.s3.us-east-1.amazonaws.com"), "arn:aws:s3:::my-bucket/*", resource, 1)
			if _, err := LoadBytes([]byte(body)); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, resource := range []string{"arn:aws:s3:::*", "arn:aws:s3:::my-bucket/a*no", "arn:aws:s3:::my-bucket/../x", "arn:aws:s3:::my-bucket/%2f"} {
		t.Run("bad-resource/"+resource, func(t *testing.T) {
			body := strings.Replace(validSigV4("my-bucket.s3.us-east-1.amazonaws.com"), "arn:aws:s3:::my-bucket/*", resource, 1)
			if _, err := LoadBytes([]byte(body)); err == nil {
				t.Fatal("expected resource rejection")
			}
		})
	}
}

func TestSigV4ProfileExclusiveCredentialValidation(t *testing.T) {
	profileOnly := strings.Replace(validSigV4("my-bucket.s3.us-east-1.amazonaws.com"), "access_key_id=\"env:ACCESS\"\nsecret_access_key=\"env:SECRET\"", "profile=\"named-profile\"", 1)
	keysOnly := validSigV4("my-bucket.s3.us-east-1.amazonaws.com")
	for name, body := range map[string]string{
		"profile alone": profileOnly,
		"keys alone":    keysOnly,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadBytes([]byte(body)); err != nil {
				t.Fatal(err)
			}
		})
	}

	for _, field := range []string{"access_key_id=\"env:ACCESS\"", "secret_access_key=\"env:SECRET\"", "session_token=\"env:SESSION\""} {
		t.Run("profile with "+strings.Split(field, "=")[0], func(t *testing.T) {
			body := strings.Replace(profileOnly, "profile=\"named-profile\"", "profile=\"named-profile\"\n"+field, 1)
			_, err := LoadBytes([]byte(body))
			var cli *clierr.Error
			if !errors.As(err, &cli) || cli.Code != clierr.EXConfig {
				t.Fatalf("error = %#v, want EX_CONFIG", err)
			}
		})
	}
}

func TestGitHubBasicValidation(t *testing.T) {
	valid := validGitHubBasic()
	if _, err := LoadBytes([]byte(valid)); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string][2]string{
		"wrong host": {"github.com", "api.github.com"}, "wildcard": {"github.com", "*.github.com"},
		"username": {"x-access-token", "octocat"}, "template": {`header_template=""`, `header_template="Bearer {secret}"`},
		"empty repos":     {`github_repositories=["Acme/repo", "Acme/*"]`, `github_repositories=[]`},
		"global wildcard": {"Acme/repo", "*/*"}, "case duplicate": {`["Acme/repo", "Acme/*"]`, `["Acme/repo", "acme/REPO"]`},
		"method": {`["GET", "POST"]`, `["GET", "DELETE"]`},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadBytes([]byte(strings.Replace(valid, change[0], change[1], 1))); err == nil {
				t.Fatal("expected github-basic rejection")
			}
		})
	}
}

func TestCredentialPassthroughConflictsAreRejected(t *testing.T) {
	t.Setenv("AWS_SECRET_ACCESS_KEY", "real-host-secret-must-not-cross")
	for name, body := range map[string]string{
		"sigv4 access key":       `[options]` + "\n" + `env_passthrough=["AWS_ACCESS_KEY_ID"]` + "\n" + validSigV4("my-bucket.s3.us-east-1.amazonaws.com"),
		"sigv4 secret key":       `[options]` + "\n" + `env_passthrough=["AWS_SECRET_ACCESS_KEY"]` + "\n" + validSigV4("my-bucket.s3.us-east-1.amazonaws.com"),
		"sigv4 session token":    `[options]` + "\n" + `env_passthrough=["AWS_SESSION_TOKEN"]` + "\n" + validSigV4("my-bucket.s3.us-east-1.amazonaws.com"),
		"sigv4 wildcard":         `[options]` + "\n" + `env_passthrough=["AWS_*"]` + "\n" + validSigV4("my-bucket.s3.us-east-1.amazonaws.com"),
		"github config count":    `[options]` + "\n" + `env_passthrough=["GIT_CONFIG_COUNT"]` + "\n" + validGitHubBasic(),
		"github config key":      `[options]` + "\n" + `env_passthrough=["GIT_CONFIG_KEY_0"]` + "\n" + validGitHubBasic(),
		"github config value":    `[options]` + "\n" + `env_passthrough=["GIT_CONFIG_VALUE_0"]` + "\n" + validGitHubBasic(),
		"github askpass":         `[options]` + "\n" + `env_passthrough=["GIT_ASKPASS"]` + "\n" + validGitHubBasic(),
		"github terminal prompt": `[options]` + "\n" + `env_passthrough=["GIT_TERMINAL_PROMPT"]` + "\n" + validGitHubBasic(),
		"github wildcard":        `[options]` + "\n" + `env_passthrough=["GIT_CONFIG_*"]` + "\n" + validGitHubBasic(),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadBytes([]byte(body)); err == nil {
				t.Fatal("expected credential passthrough conflict")
			}
		})
	}
}

func TestMTLSValidation(t *testing.T) {
	valid := validMTLS("partner.example.com")
	if _, err := LoadBytes([]byte(valid)); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string][2]string{
		"wildcard":          {"partner.example.com", "*.example.com"},
		"lower method":      {`method="GET"`, `method="get"`},
		"empty rules":       {`rules=[{method="GET", path_prefix="/v1/limited/"}, {method="POST", path_prefix="/v1/limited/"}]`, `rules=[]`},
		"relative prefix":   {`path_prefix="/v1/limited/"`, `path_prefix="v1"`},
		"encoded separator": {`path_prefix="/v1/limited/"`, `path_prefix="/v1%2fprivate"`},
		"traversal":         {`path_prefix="/v1/limited/"`, `path_prefix="/v1/../private"`},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadBytes([]byte(strings.Replace(valid, change[0], change[1], 1))); err == nil {
				t.Fatal("expected mTLS rejection")
			}
		})
	}
}

func TestCredentialMetadataValidation(t *testing.T) {
	valid := validMTLS("partner.example.com") + "\nissuer=\"https://issuer.example\"\nbootstrap_ref=\"vault:bootstrap\"\nmax_ttl=\"1h\""
	if _, err := LoadBytes([]byte(valid)); err != nil {
		t.Fatal(err)
	}
	for _, change := range [][2]string{{`max_ttl="1h"`, `max_ttl="0s"`}, {`bootstrap_ref="vault:bootstrap"`, `bootstrap_ref="file:/secret"`}, {`issuer="https://issuer.example"`, ``}} {
		if _, err := LoadBytes([]byte(strings.Replace(valid, change[0], change[1], 1))); err == nil {
			t.Fatal("expected metadata rejection")
		}
	}
}

func validSigV4(host string) string {
	return `[[sigv4]]
host="` + host + `"
access_key_id="env:ACCESS"
secret_access_key="env:SECRET"
account_id="123456789012"
service="s3"
region="us-east-1"
allowed_methods=["GET", "HEAD", "PUT"]
allowed_operations=["s3:GetObject", "s3:HeadObject", "s3:PutObject"]
allowed_resources=["arn:aws:s3:::my-bucket/*"]
max_body_bytes=1`
}

func validMTLS(host string) string {
	return `[[mtls]]
host="` + host + `"
client_cert="env:CERT"
client_key="env:KEY"
rules=[{method="GET", path_prefix="/v1/limited/"}, {method="POST", path_prefix="/v1/limited/"}]`
}

func TestMTLSLegacyArraysRejectedWithPositionAndPairExample(t *testing.T) {
	for _, tc := range []struct {
		name, legacyKey string
		line            int
	}{
		{"methods", `allowed_methods = ["GET"]`, 6},
		{"empty prefixes", `allowed_path_prefixes = []`, 6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeDocument("policy.toml", []byte(`[[mtls]]
host = "partner.example"
client_cert = "env:CERT"
client_key = "env:KEY"
rules = [{ method = "GET", path_prefix = "/v1/" }]
`+tc.legacyKey+"\n"))
			if err == nil {
				t.Fatal("legacy mTLS arrays were accepted")
			}
			var cli *clierr.Error
			if !errors.As(err, &cli) || cli.Code != clierr.EXConfig || cli.Where == nil {
				t.Fatalf("error = %#v, want positioned EX_CONFIG", err)
			}
			if cli.Where.Path != "policy.toml" || cli.Where.Line != tc.line || cli.Where.Column != 1 || cli.Fix != "cove config edit" {
				t.Fatalf("location/fix = %#v/%q, want policy.toml:%d:1 and cove config edit", cli.Where, cli.Fix, tc.line)
			}
			got := cli.Where.Detail
			for _, want := range []string{strings.Split(tc.legacyKey, " ")[0], `rules = [{ method = "GET", path_prefix = "/v1/x/" }]`} {
				if !strings.Contains(got, want) {
					t.Fatalf("error %q does not contain %q", got, want)
				}
			}
		})
	}
}

func TestMTLSRulesValidation(t *testing.T) {
	valid := validMTLS("partner.example")
	for _, change := range [][2]string{
		{`rules=[{method="GET", path_prefix="/v1/limited/"}, {method="POST", path_prefix="/v1/limited/"}]`, `rules=[]`},
		{`method="GET"`, `method="get"`},
		{`{method="POST", path_prefix="/v1/limited/"}`, `{method="GET", path_prefix="/v1/limited/"}`},
		{`path_prefix="/v1/limited/"}`, `path_prefix="/v1/%2f/"}`},
	} {
		if _, err := LoadBytes([]byte(strings.Replace(valid, change[0], change[1], 1))); err == nil {
			t.Fatalf("accepted invalid mTLS rule after %q -> %q", change[0], change[1])
		}
	}
}

func validGitHubBasic() string {
	return `[[inject]]
host="github.com"
transform="github-basic"
header_name="Authorization"
header_template=""
basic_username="x-access-token"
secret="env:TOKEN"
github_repositories=["Acme/repo", "Acme/*"]
allowed_methods=["GET", "POST"]`
}
