package box

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func buildEnv(d Directives) []string {
	path := "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	if prefixes := runtimePathPrefixes(d.RuntimeMount); len(prefixes) > 0 {
		path = strings.Join(append(prefixes, path), ":")
	}
	env := []string{
		"HOME=/root",
		"USER=root",
		"LOGNAME=root",
		"PATH=" + path,
		"TMPDIR=/tmp",
		"LANG=C.UTF-8",
		"NODE_EXTRA_CA_CERTS=/etc/ssl/certs/cove-ca.pem",
		"SSL_CERT_FILE=/etc/ssl/certs/cove-ca-bundle.pem",
		"SSL_CERT_DIR=/etc/ssl/certs",
		"REQUESTS_CA_BUNDLE=/etc/ssl/certs/cove-ca-bundle.pem",
		"CURL_CA_BUNDLE=/etc/ssl/certs/cove-ca-bundle.pem",
		"GIT_SSL_CAINFO=/etc/ssl/certs/cove-ca-bundle.pem",
		"CODEX_CA_CERTIFICATE=/etc/ssl/certs/cove-ca.pem",
	}
	if d.Term != "" {
		env = append(env, "TERM="+d.Term)
	}
	if d.ProxyEnabled {
		proxy := "http://127.0.0.1:" + itoa(d.ProxyPort)
		env = append(env,
			"HTTPS_PROXY="+proxy,
			"HTTP_PROXY="+proxy,
			"https_proxy="+proxy,
			"http_proxy="+proxy,
			"NO_PROXY=127.0.0.1,localhost",
			"no_proxy=127.0.0.1,localhost",
		)
	}
	dummyEnv := make(map[string]string, len(d.DummyEnv)+len(d.Inject))
	for key, value := range d.DummyEnv {
		dummyEnv[key] = value
	}
	for _, st := range d.Inject {
		if st.DummyEnv != "" {
			if _, exists := dummyEnv[st.DummyEnv]; !exists {
				value := st.DummyValue
				if value == "" {
					value = "cove-dummy-do-not-use"
				}
				dummyEnv[st.DummyEnv] = value
			}
		}
		if st.BaseURLEnv != "" && st.BaseURLValue != "" && !strings.HasSuffix(st.BaseURLValue, ":0") {
			env = append(env, st.BaseURLEnv+"="+st.BaseURLValue)
		}
	}
	for k, v := range d.EnvPassthrough {
		env = append(env, k+"="+v)
	}
	keys := make([]string, 0, len(dummyEnv))
	for key := range dummyEnv {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		env = append(env, key+"="+dummyEnv[key])
	}
	env = appendGitHubDummyCredentialConfig(env, d.Inject)
	for _, key := range []string{"LC_ALL", "LC_CTYPE", "LC_MESSAGES"} {
		if v := os.Getenv(key); v != "" {
			env = append(env, key+"="+v)
		}
	}
	return env
}

// BuildEnv exposes the box environment composition for callers which need to
// execute an in-box-equivalent command without starting a namespace.
func BuildEnv(d Directives) []string {
	return buildEnv(d)
}

func appendGitHubDummyCredentialConfig(env []string, inject []InjectDirective) []string {
	var dummy string
	for _, st := range inject {
		if st.Transform != "github-basic" {
			continue
		}
		dummy = st.DummyValue
		if dummy == "" {
			dummy = "cove-dummy-do-not-use"
		}
		break
	}
	if dummy == "" {
		return env
	}

	entries := [][2]string{
		{"credential.https://github.com.helper", gitHubDummyCredentialHelper(dummy)},
		{"credential.https://github.com.useHttpPath", "true"},
	}
	// Command-scope settings must be contiguous and their count must include
	// any settings cove added before these entries.
	count := 0
	for _, item := range env {
		if strings.HasPrefix(item, "GIT_CONFIG_KEY_") {
			count++
		}
	}
	for _, entry := range entries {
		env = append(env,
			"GIT_CONFIG_KEY_"+itoa(count)+"="+entry[0],
			"GIT_CONFIG_VALUE_"+itoa(count)+"="+entry[1],
		)
		count++
	}
	env = append(env, "GIT_CONFIG_COUNT="+itoa(count), "GIT_TERMINAL_PROMPT=0")
	return env
}

func gitHubDummyCredentialHelper(dummy string) string {
	// dummy is an in-box literal, but quote it defensively so a configured
	// value cannot change the helper program.
	quoted := "'" + strings.ReplaceAll(dummy, "'", "'\\\"'\\\"'") + "'"
	return "!f() { op=\"$1\"; [ \"$op\" = get ] || exit 0; protocol= host=; " +
		"while IFS='=' read -r key value; do case \"$key\" in protocol) protocol=\"$value\";; host) host=\"$value\";; esac; done; " +
		"[ \"$protocol\" = https ] && [ \"$host\" = github.com ] || exit 0; " +
		"printf '%s\\n' username=x-access-token; printf '%s\\n' password=" + quoted + "; }; f"
}

func runtimePathPrefixes(mounts []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, mount := range mounts {
		dir := filepath.Clean(mount)
		if filepath.Base(dir) != "bin" {
			bin := filepath.Join(dir, "bin")
			if st, err := os.Stat(bin); err == nil && st.IsDir() {
				dir = bin
			}
		}
		if dir == "." || dir == string(filepath.Separator) || seen[dir] {
			continue
		}
		seen[dir] = true
		out = append(out, dir)
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
