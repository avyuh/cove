package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Options Options        `toml:"options"`
	Allow   []string       `toml:"allow"`
	Inject  []InjectStanza `toml:"inject"`
	SigV4   []SigV4Stanza  `toml:"sigv4"`
	MTLS    []MTLSStanza   `toml:"mtls"`
	Expose  []ExposeStanza `toml:"expose"`
	Managed ManagedConfig  `toml:"managed"`

	AllowRules []AllowRule `toml:"-"`
}

type Options struct {
	TmpSize        string   `toml:"tmp_size"`
	ProxyPort      int      `toml:"proxy_port"`
	Audit          bool     `toml:"audit"`
	CredMount      []string `toml:"cred_mount"`
	RuntimeMount   []string `toml:"runtime_mount"`
	EnvPassthrough []string `toml:"env_passthrough"`
}

type ExposeStanza struct {
	Name   string `toml:"name"`
	Path   string `toml:"path"`
	Mode   string `toml:"mode"`
	Reason string `toml:"reason"`
}

type InjectStanza struct {
	Name               string   `toml:"name"`
	Host               string   `toml:"host"`
	HeaderName         string   `toml:"header_name"`
	HeaderTemplate     string   `toml:"header_template"`
	Secret             string   `toml:"secret"`
	StripHeaders       []string `toml:"strip_headers"`
	DummyEnv           string   `toml:"dummy_env"`
	DummyValue         string   `toml:"dummy_value"`
	BaseURLEnv         string   `toml:"base_url_env"`
	BaseURLValue       string   `toml:"base_url_value"`
	ALPN               string   `toml:"alpn"`
	Mode               string   `toml:"mode"`
	Transform          string   `toml:"transform"`
	BasicUsername      string   `toml:"basic_username"`
	GitHubRepositories []string `toml:"github_repositories"`
	AllowedMethods     []string `toml:"allowed_methods"`
	Issuer             string   `toml:"issuer"`
	MaxTTL             string   `toml:"max_ttl"`
	BootstrapRef       string   `toml:"bootstrap_ref"`

	Port int `toml:"-"`
}

type SigV4Stanza struct {
	Name string `toml:"name"`
	Host string `toml:"host"`
	// Profile delegates credential refresh to the AWS SDK on the host. It is
	// deliberately an alternative to file/env secret refs, never an addition.
	Profile           string   `toml:"profile"`
	AccessKeyID       string   `toml:"access_key_id"`
	SecretAccessKey   string   `toml:"secret_access_key"`
	SessionToken      string   `toml:"session_token"`
	AccountID         string   `toml:"account_id"`
	Service           string   `toml:"service"`
	Region            string   `toml:"region"`
	AllowedMethods    []string `toml:"allowed_methods"`
	AllowedOperations []string `toml:"allowed_operations"`
	AllowedResources  []string `toml:"allowed_resources"`
	AllowUnsigned     bool     `toml:"allow_unsigned_payload"`
	MaxBodyBytes      int64    `toml:"max_body_bytes"`
	ALPN              string   `toml:"alpn"`
	Issuer            string   `toml:"issuer"`
	MaxTTL            string   `toml:"max_ttl"`
	BootstrapRef      string   `toml:"bootstrap_ref"`
	Port              int      `toml:"-"`
}

type MTLSStanza struct {
	Name                  string     `toml:"name"`
	Host                  string     `toml:"host"`
	ClientCert            string     `toml:"client_cert"`
	ClientKey             string     `toml:"client_key"`
	Rules                 []MTLSRule `toml:"rules"`
	LegacyAllowedMethods  []string   `toml:"allowed_methods"`
	LegacyAllowedPrefixes []string   `toml:"allowed_path_prefixes"`
	ALPN                  string     `toml:"alpn"`
	Issuer                string     `toml:"issuer"`
	MaxTTL                string     `toml:"max_ttl"`
	BootstrapRef          string     `toml:"bootstrap_ref"`
	Port                  int        `toml:"-"`
}

// MTLSRule is one exact HTTP method and path-prefix authorization pair.
// Pairing is deliberate: independent method and prefix lists over-grant.
type MTLSRule struct {
	Method     string `toml:"method"`
	PathPrefix string `toml:"path_prefix"`
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
	SigV4   []SigV4Stanza  `toml:"sigv4"`
	MTLS    []MTLSStanza   `toml:"mtls"`
	Expose  []ExposeStanza `toml:"expose"`
	Managed rawManaged     `toml:"managed"`
}

// ManagedConfig is the cove-owned portion of the configuration. It is kept
// separate from user-authored policies so edits never need to reformat them.
type ManagedConfig struct {
	Version int
	Allow   []NamedAllow
	Block   []PolicyRef
	Inject  []InjectStanza
	SigV4   []SigV4Stanza
	MTLS    []MTLSStanza
	Expose  []ExposeStanza
}

type rawManaged struct {
	Version int            `toml:"version"`
	Allow   []NamedAllow   `toml:"allow"`
	Block   []PolicyRef    `toml:"block"`
	Inject  []InjectStanza `toml:"inject"`
	SigV4   []SigV4Stanza  `toml:"sigv4"`
	MTLS    []MTLSStanza   `toml:"mtls"`
	Expose  []ExposeStanza `toml:"expose"`
}

type NamedAllow struct {
	Name string `toml:"name"`
	Host string `toml:"host"`
}

type PolicyRef struct {
	Kind string `toml:"kind"`
	Host string `toml:"host"`
}

type rawOptions struct {
	Options
	Allow []string `toml:"allow"`
}

func Load(path string) (*Config, error) {
	doc, err := LoadDocument(path)
	if err != nil {
		return nil, err
	}
	return doc.Config, nil
}

// LoadDocument reads the configured policy while retaining its source context.
func LoadDocument(path string) (*Document, error) {
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
	return DecodeDocument(path, data)
}

// LoadBytes remains for in-memory callers; use DecodeDocument when a path is known.
func LoadBytes(data []byte) (*Config, error) {
	doc, err := DecodeDocument("", data)
	if err != nil {
		return nil, err
	}
	return doc.Config, nil
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
	if err := validateExposes(c.Expose); err != nil {
		return err
	}
	if err := validateRuntimeMounts(c.Options.RuntimeMount); err != nil {
		return err
	}
	if err := validateEnvPassthrough(c.Options.EnvPassthrough); err != nil {
		return err
	}

	claims := map[string]string{}
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
		claims[key] = "allow"
		rules = append(rules, r)
	}
	c.AllowRules = rules

	dummyValues := map[string]string{}
	for i := range c.Inject {
		st := &c.Inject[i]
		r, err := ParseRule(st.Host)
		if err != nil {
			return fmt.Errorf("inject host %q: %w", st.Host, err)
		}
		st.Port = r.Port
		if err := claimPolicyRule(claims, r, st.Host, "inject"); err != nil {
			return err
		}
		if err := validateInjectStanza(st, r); err != nil {
			return err
		}
		if st.DummyEnv != "" {
			if previous, ok := dummyValues[st.DummyEnv]; ok && previous != st.DummyValue {
				return fmt.Errorf("dummy_env %q has conflicting dummy values", st.DummyEnv)
			}
			dummyValues[st.DummyEnv] = st.DummyValue
		}
	}
	for i := range c.SigV4 {
		st := &c.SigV4[i]
		r, err := ParseRule(st.Host)
		if err != nil {
			return fmt.Errorf("sigv4 host %q: %w", st.Host, err)
		}
		st.Port = r.Port
		if err := claimPolicyRule(claims, r, st.Host, "sigv4"); err != nil {
			return err
		}
		if err := validateSigV4Stanza(st, r); err != nil {
			return err
		}
	}
	for i := range c.MTLS {
		st := &c.MTLS[i]
		r, err := ParseRule(st.Host)
		if err != nil {
			return fmt.Errorf("mtls host %q: %w", st.Host, err)
		}
		st.Port = r.Port
		if err := claimPolicyRule(claims, r, st.Host, "mtls"); err != nil {
			return err
		}
		if err := validateMTLSStanza(st, r); err != nil {
			return err
		}
	}
	if err := validateCredentialEnvPassthrough(c.Options.EnvPassthrough, len(c.SigV4) > 0, hasGitHubBasic(c.Inject)); err != nil {
		return err
	}
	return nil
}

func hasGitHubBasic(inject []InjectStanza) bool {
	for _, st := range inject {
		if st.Transform == "github-basic" {
			return true
		}
	}
	return false
}

func validateCredentialEnvPassthrough(entries []string, sigV4, githubBasic bool) error {
	if sigV4 {
		for _, pattern := range entries {
			for _, name := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"} {
				if envPassthroughMatches(pattern, name) {
					return fmt.Errorf("env_passthrough %q conflicts with SigV4 dummy credential %s", pattern, name)
				}
			}
		}
	}
	if githubBasic {
		for _, pattern := range entries {
			if envPassthroughMatches(pattern, "GIT_CONFIG_COUNT") ||
				envPassthroughMatchesPrefix(pattern, "GIT_CONFIG_KEY_") ||
				envPassthroughMatchesPrefix(pattern, "GIT_CONFIG_VALUE_") ||
				envPassthroughMatches(pattern, "GIT_ASKPASS") ||
				envPassthroughMatches(pattern, "GIT_TERMINAL_PROMPT") {
				return fmt.Errorf("env_passthrough %q conflicts with github-basic command settings", pattern)
			}
		}
	}
	return nil
}

func envPassthroughMatches(pattern, name string) bool {
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(name, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == name
}

// envPassthroughMatchesPrefix reports whether a permitted exact/trailing-star
// pattern could pass any setting under prefix.
func envPassthroughMatchesPrefix(pattern, prefix string) bool {
	if strings.HasSuffix(pattern, "*") {
		pattern = strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(prefix, pattern) || strings.HasPrefix(pattern, prefix)
	}
	return strings.HasPrefix(pattern, prefix)
}

func claimPolicyRule(claims map[string]string, r AllowRule, host, kind string) error {
	key := ruleKey(r)
	if previous, ok := claims[key]; ok {
		return fmt.Errorf("host %q appears in both %s and %s", host, previous, kind)
	}
	claims[key] = kind
	return nil
}

func validateInjectStanza(st *InjectStanza, r AllowRule) error {
	if st.Transform == "" {
		st.Transform = "template"
	}
	if st.DummyValue == "" {
		st.DummyValue = "cove-dummy-ask-the-human-to-run-cove-add"
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
	if st.Secret == "" {
		return fmt.Errorf("inject %q missing secret", st.Host)
	}
	if !validSecretRef(st.Secret) {
		return fmt.Errorf("inject %q has unsupported secret ref %q", st.Host, st.Secret)
	}
	switch st.Transform {
	case "template":
		if st.HeaderName == "" {
			return fmt.Errorf("inject %q missing header_name", st.Host)
		}
		if !strings.Contains(st.HeaderTemplate, "{secret}") {
			return fmt.Errorf("inject %q header_template must contain {secret}", st.Host)
		}
	case "github-basic":
		if r.Wildcard || r.Host != "github.com" {
			return fmt.Errorf("inject %q github-basic requires exact github.com host", st.Host)
		}
		if !strings.EqualFold(st.HeaderName, "Authorization") {
			return fmt.Errorf("inject %q github-basic requires Authorization header_name", st.Host)
		}
		if st.BasicUsername != "x-access-token" {
			return fmt.Errorf("inject %q github-basic requires basic_username x-access-token", st.Host)
		}
		if st.HeaderTemplate != "" {
			return fmt.Errorf("inject %q github-basic does not permit header_template", st.Host)
		}
		if len(st.GitHubRepositories) == 0 {
			return fmt.Errorf("inject %q github-basic requires github_repositories", st.Host)
		}
		seen := map[string]bool{}
		for _, repo := range st.GitHubRepositories {
			if err := validateGitHubRepository(repo); err != nil {
				return fmt.Errorf("inject %q github repository %q: %w", st.Host, repo, err)
			}
			key := strings.ToLower(repo)
			if seen[key] {
				return fmt.Errorf("inject %q duplicate github repository %q", st.Host, repo)
			}
			seen[key] = true
		}
		if len(st.AllowedMethods) == 0 {
			return fmt.Errorf("inject %q github-basic requires allowed_methods", st.Host)
		}
		for _, method := range st.AllowedMethods {
			if method != "GET" && method != "POST" {
				return fmt.Errorf("inject %q github-basic method %q is not allowed", st.Host, method)
			}
		}
	default:
		return fmt.Errorf("inject %q transform %q is not supported", st.Host, st.Transform)
	}
	return validateCredentialMetadata("inject", st.Host, st.Issuer, st.MaxTTL, st.BootstrapRef)
}

func validateGitHubRepository(repo string) error {
	parts := strings.Split(repo, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" || repo == "*/*" {
		return errors.New("must be owner/repo or owner/*")
	}
	for i, p := range parts {
		if i == 1 && p == "*" {
			continue
		}
		if p == "." || p == ".." || strings.ContainsAny(p, "%\\") || !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`).MatchString(p) {
			return errors.New("has invalid component")
		}
	}
	return nil
}

var regionPattern = regexp.MustCompile(`^[a-z0-9-]+$`)
var accountIDPattern = regexp.MustCompile(`^[0-9]{12}$`)
var s3BucketPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]*[a-z0-9]$`)

func validateSigV4Stanza(st *SigV4Stanza, r AllowRule) error {
	endpointRegion, bucket, err := parseS3EndpointRule(r)
	if err != nil {
		return fmt.Errorf("sigv4 %q: %w", st.Host, err)
	}
	if st.Service != "s3" {
		return fmt.Errorf("sigv4 %q service must be s3", st.Host)
	}
	if !regionPattern.MatchString(st.Region) || st.Region != endpointRegion {
		return fmt.Errorf("sigv4 %q region must match S3 endpoint region", st.Host)
	}
	if !accountIDPattern.MatchString(st.AccountID) {
		return fmt.Errorf("sigv4 %q account_id must be a 12-digit value", st.Host)
	}
	if st.Profile != "" {
		if st.AccessKeyID != "" || st.SecretAccessKey != "" || st.SessionToken != "" {
			return fmt.Errorf("sigv4 %q profile is exclusive with access_key_id, secret_access_key, and session_token", st.Host)
		}
	} else {
		if st.AccessKeyID == "" || !validSecretRef(st.AccessKeyID) {
			return fmt.Errorf("sigv4 %q missing or invalid access_key_id", st.Host)
		}
		if st.SecretAccessKey == "" || !validSecretRef(st.SecretAccessKey) {
			return fmt.Errorf("sigv4 %q missing or invalid secret_access_key", st.Host)
		}
		if st.SessionToken != "" && !validSecretRef(st.SessionToken) {
			return fmt.Errorf("sigv4 %q has unsupported session_token ref %q", st.Host, st.SessionToken)
		}
	}
	if len(st.AllowedMethods) == 0 || len(st.AllowedOperations) == 0 || len(st.AllowedResources) == 0 {
		return fmt.Errorf("sigv4 %q requires methods, operations, and resources", st.Host)
	}
	if st.MaxBodyBytes < 1 || st.MaxBodyBytes > 1<<30 {
		return fmt.Errorf("sigv4 %q max_body_bytes must be between 1 and 1073741824", st.Host)
	}
	if st.ALPN == "" {
		st.ALPN = "h2"
	}
	if st.ALPN != "h2" && st.ALPN != "http/1.1" {
		return fmt.Errorf("sigv4 %q alpn must be h2 or http/1.1", st.Host)
	}
	methodSet := map[string]bool{}
	for _, m := range st.AllowedMethods {
		if m != strings.ToUpper(m) || !sigV4MethodAllowed(m) {
			return fmt.Errorf("sigv4 %q method %q is not supported", st.Host, m)
		}
		methodSet[m] = true
	}
	operationSet := map[string]bool{}
	for _, op := range st.AllowedOperations {
		if !sigV4OperationAllowed(op) {
			return fmt.Errorf("sigv4 %q operation %q is not supported", st.Host, op)
		}
		operationSet[op] = true
	}
	for op := range operationSet {
		if !operationHasMethod(op, methodSet) {
			return fmt.Errorf("sigv4 %q operation %q has no compatible method", st.Host, op)
		}
	}
	for _, resource := range st.AllowedResources {
		resourceBucket, err := validateS3ResourcePattern(resource)
		if err != nil {
			return fmt.Errorf("sigv4 %q resource %q: %w", st.Host, resource, err)
		}
		if bucket != "" && resourceBucket != bucket {
			return fmt.Errorf("sigv4 %q resource %q does not cover virtual-host bucket %q", st.Host, resource, bucket)
		}
	}
	return validateCredentialMetadata("sigv4", st.Host, st.Issuer, st.MaxTTL, st.BootstrapRef)
}

// parseS3EndpointRule accepts only the endpoint forms whose region and resource
// interpretation are unambiguous in v1.
func parseS3EndpointRule(r AllowRule) (region, bucket string, err error) {
	host := r.Host
	if excludedS3EndpointRule(host) {
		return "", "", errors.New("unsupported S3 endpoint form")
	}
	if r.Wildcard {
		parts := strings.Split(host, ".")
		if len(parts) == 4 && parts[0] == "s3" && parts[2] == "amazonaws" && parts[3] == "com" && supportedS3EndpointRegion(parts[1]) {
			return parts[1], "", nil
		}
		return "", "", errors.New("wildcard is only permitted for *.s3.<region>.amazonaws.com")
	}
	if host == "s3.amazonaws.com" {
		return "us-east-1", "", nil
	}
	parts := strings.Split(host, ".")
	if len(parts) == 4 && parts[0] == "s3" && parts[2] == "amazonaws" && parts[3] == "com" && supportedS3EndpointRegion(parts[1]) {
		return parts[1], "", nil
	}
	if len(parts) == 5 && parts[1] == "s3" && parts[3] == "amazonaws" && parts[4] == "com" && s3BucketPattern.MatchString(parts[0]) && supportedS3EndpointRegion(parts[2]) {
		return parts[2], parts[0], nil
	}
	return "", "", errors.New("unsupported S3 endpoint form")
}

func supportedS3EndpointRegion(region string) bool {
	if !regionPattern.MatchString(region) {
		return false
	}
	for _, prefix := range []string{"us-gov-", "cn-", "us-iso-", "us-isob-", "us-isof-", "eu-isoe-"} {
		if strings.HasPrefix(region, prefix) {
			return false
		}
	}
	return true
}

func excludedS3EndpointRule(host string) bool {
	if strings.HasSuffix(host, ".amazonaws.com.cn") {
		return true
	}
	for _, marker := range []string{
		"s3-accelerate", "s3.dualstack.", ".s3.dualstack.", "s3-fips", "s3-accesspoint",
		"s3-outposts", "s3-control", ".mrap.", ".accesspoint.s3-global.",
	} {
		if strings.Contains(host, marker) {
			return true
		}
	}
	return false
}

func validateS3ResourcePattern(resource string) (string, error) {
	const prefix = "arn:aws:s3:::"
	if !strings.HasPrefix(resource, prefix) {
		return "", errors.New("must be an arn:aws:s3::: resource")
	}
	rest := strings.TrimPrefix(resource, prefix)
	parts := strings.SplitN(rest, "/", 2)
	bucket := parts[0]
	if !s3BucketPattern.MatchString(bucket) || bucket == "*" {
		return "", errors.New("has invalid bucket")
	}
	if len(parts) == 2 {
		key := parts[1]
		if key == "" || strings.Contains(key, "\\") || strings.Contains(strings.ToLower(key), "%2f") || strings.Contains(strings.ToLower(key), "%5c") {
			return "", errors.New("has invalid key pattern")
		}
		for _, seg := range strings.Split(key, "/") {
			if seg == "." || seg == ".." {
				return "", errors.New("has traversal")
			}
		}
		if strings.Count(key, "*") > 1 || (strings.Contains(key, "*") && !strings.HasSuffix(key, "*")) {
			return "", errors.New("permits only one trailing wildcard")
		}
	}
	return bucket, nil
}

func sigV4MethodAllowed(method string) bool {
	return method == "GET" || method == "HEAD" || method == "PUT" || method == "DELETE"
}
func sigV4OperationAllowed(op string) bool {
	switch op {
	case "s3:GetObject", "s3:HeadObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket", "s3:CopyObject":
		return true
	}
	return false
}
func operationHasMethod(op string, methods map[string]bool) bool {
	switch op {
	case "s3:GetObject", "s3:ListBucket":
		return methods["GET"]
	case "s3:HeadObject":
		return methods["HEAD"]
	case "s3:PutObject", "s3:CopyObject":
		return methods["PUT"]
	case "s3:DeleteObject":
		return methods["DELETE"]
	}
	return false
}

func validateMTLSStanza(st *MTLSStanza, r AllowRule) error {
	if r.Wildcard {
		return fmt.Errorf("mtls %q does not permit wildcard hosts", st.Host)
	}
	if st.ClientCert == "" || !validSecretRef(st.ClientCert) {
		return fmt.Errorf("mtls %q missing or invalid client_cert", st.Host)
	}
	if st.ClientKey == "" || !validSecretRef(st.ClientKey) {
		return fmt.Errorf("mtls %q missing or invalid client_key", st.Host)
	}
	if st.LegacyAllowedMethods != nil {
		return fmt.Errorf("mtls %q allowed_methods is no longer supported; use rules = [{ method = \"GET\", path_prefix = \"/v1/x/\" }]", st.Host)
	}
	if st.LegacyAllowedPrefixes != nil {
		return fmt.Errorf("mtls %q allowed_path_prefixes is no longer supported; use rules = [{ method = \"GET\", path_prefix = \"/v1/x/\" }]", st.Host)
	}
	if len(st.Rules) == 0 {
		return fmt.Errorf("mtls %q requires at least one rule", st.Host)
	}
	seen := map[string]bool{}
	for _, rule := range st.Rules {
		if rule.Method == "" || rule.Method != strings.ToUpper(rule.Method) {
			return fmt.Errorf("mtls %q method %q must be uppercase", st.Host, rule.Method)
		}
		if err := validateHTTPPathPrefix(rule.PathPrefix); err != nil {
			return fmt.Errorf("mtls %q path prefix %q: %w", st.Host, rule.PathPrefix, err)
		}
		key := rule.Method + "\x00" + rule.PathPrefix
		if seen[key] {
			return fmt.Errorf("mtls %q has duplicate rule %s %s", st.Host, rule.Method, rule.PathPrefix)
		}
		seen[key] = true
	}
	// Legacy fields are detection-only and must never reach the matcher.
	st.LegacyAllowedMethods = nil
	st.LegacyAllowedPrefixes = nil
	if st.ALPN == "" {
		st.ALPN = "h2"
	}
	if st.ALPN != "h2" && st.ALPN != "http/1.1" {
		return fmt.Errorf("mtls %q alpn must be h2 or http/1.1", st.Host)
	}
	return validateCredentialMetadata("mtls", st.Host, st.Issuer, st.MaxTTL, st.BootstrapRef)
}

func validateHTTPPathPrefix(prefix string) error {
	if prefix == "" || !strings.HasPrefix(prefix, "/") || strings.ContainsAny(prefix, "?#\\") {
		return errors.New("must be an absolute path without query or fragment")
	}
	lower := strings.ToLower(prefix)
	if strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") {
		return errors.New("contains encoded separator")
	}
	trimmed := strings.TrimSuffix(prefix, "/")
	for _, segment := range strings.Split(trimmed, "/") {
		if segment == "." || segment == ".." {
			return errors.New("contains traversal")
		}
	}
	if strings.Contains(prefix, "//") {
		return errors.New("must be clean")
	}
	return nil
}

func validateCredentialMetadata(kind, host, issuer, maxTTL, bootstrapRef string) error {
	if maxTTL != "" {
		if d, err := time.ParseDuration(maxTTL); err != nil || d <= 0 {
			return fmt.Errorf("%s %q max_ttl must be a positive duration", kind, host)
		}
	}
	if (issuer == "") != (bootstrapRef == "") {
		return fmt.Errorf("%s %q issuer and bootstrap_ref must be set together", kind, host)
	}
	if bootstrapRef != "" {
		if strings.HasPrefix(bootstrapRef, "file:") || strings.HasPrefix(bootstrapRef, "env:") || strings.HasPrefix(bootstrapRef, "json:") || strings.ContainsAny(bootstrapRef, " \t\r\n") {
			return fmt.Errorf("%s %q has invalid bootstrap_ref", kind, host)
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
	if err := validateRuleHost(matchHost); err != nil {
		return AllowRule{}, err
	}
	return AllowRule{Pattern: raw, Host: matchHost, Wildcard: wild, Port: port}, nil
}

// ParseExactRule is the command/response boundary for a concrete network
// target. Unlike ParseRule it rejects wildcard syntax, so its result can be
// safely rendered in a shell-shaped instruction.
func ParseExactRule(raw string) (AllowRule, error) {
	r, err := ParseRule(raw)
	if err != nil {
		return AllowRule{}, err
	}
	if r.Wildcard {
		return AllowRule{}, errors.New("wildcards are not accepted here")
	}
	return r, nil
}

// FormatExactRule returns the canonical text for an exact rule. IPv6 is kept
// bracketed when a non-default port is present so it cannot be ambiguous.
func FormatExactRule(r AllowRule) string {
	host := r.Host
	if r.Port != 443 {
		return net.JoinHostPort(host, strconv.Itoa(r.Port))
	}
	return host
}

func validateRuleHost(host string) error {
	if ip := net.ParseIP(host); ip != nil {
		return nil
	}
	if len(host) > 253 || strings.HasSuffix(host, ".") {
		return errors.New("invalid DNS host")
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("invalid DNS host")
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return errors.New("invalid DNS host")
			}
		}
	}
	return nil
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

func validateExposes(entries []ExposeStanza) error {
	seen := map[string]string{}
	for _, e := range entries {
		if e.Path == "" || e.Reason == "" {
			return fmt.Errorf("expose %q requires path and reason", e.Name)
		}
		if e.Mode != "ro" && e.Mode != "rw" {
			return fmt.Errorf("expose %q mode must be ro or rw", e.Path)
		}
		if err := validateCredMounts([]string{e.Path}); err != nil {
			return fmt.Errorf("expose %q: %w", e.Path, err)
		}
		key := filepath.Clean(strings.TrimPrefix(e.Path, "~/"))
		if prior, ok := seen[key]; ok {
			return fmt.Errorf("duplicate expose path %q has conflicting modes %s and %s", e.Path, prior, e.Mode)
		}
		seen[key] = e.Mode
	}
	return nil
}

func validateRuntimeMounts(entries []string) error {
	home, _ := os.UserHomeDir()
	for _, e := range entries {
		if strings.Contains(e, "*") {
			return fmt.Errorf("runtime_mount %q is too broad", e)
		}
		if strings.HasSuffix(e, ":rw") {
			return fmt.Errorf("runtime_mount %q is read-only only; use PATH without :rw", e)
		}
		path := e
		if strings.HasPrefix(path, "~/") {
			path = filepath.Join(home, strings.TrimPrefix(path, "~/"))
		}
		clean := filepath.Clean(path)
		if path == "" || clean == "." || clean == "~" || clean == "/" ||
			clean == "/home" || clean == "/root" || clean == "/etc" {
			return fmt.Errorf("runtime_mount %q is too broad", e)
		}
		if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			return fmt.Errorf("runtime_mount %q is too broad", e)
		}
		if filepath.IsAbs(clean) && home != "" {
			homeClean := filepath.Clean(home)
			if sameOrAncestor(clean, homeClean) {
				return fmt.Errorf("runtime_mount %q must not be HOME or an ancestor of HOME", e)
			}
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

func sameOrAncestor(path, child string) bool {
	path = filepath.Clean(path)
	child = filepath.Clean(child)
	if path == child {
		return true
	}
	rel, err := filepath.Rel(path, child)
	return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
