package box

import (
	"os"
	"strings"
)

func buildEnv(d Directives) []string {
	env := []string{
		"HOME=/root",
		"USER=root",
		"LOGNAME=root",
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
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
	for _, st := range d.Inject {
		if st.DummyEnv != "" {
			val := st.DummyValue
			if val == "" {
				val = "cove-dummy-do-not-use"
			}
			env = append(env, st.DummyEnv+"="+val)
		}
		if st.BaseURLEnv != "" && st.BaseURLValue != "" && !strings.HasSuffix(st.BaseURLValue, ":0") {
			env = append(env, st.BaseURLEnv+"="+st.BaseURLValue)
		}
	}
	for k, v := range d.EnvPassthrough {
		env = append(env, k+"="+v)
	}
	for _, key := range []string{"LC_ALL", "LC_CTYPE", "LC_MESSAGES"} {
		if v := os.Getenv(key); v != "" {
			env = append(env, key+"="+v)
		}
	}
	return env
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
