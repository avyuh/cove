package proxy

import (
	"net"
	"strconv"
	"strings"
	"testing"

	"cove/internal/config"
)

func FuzzHostRenderAndValidate(f *testing.F) {
	f.Add([]byte("api.example.com"), uint16(443))
	f.Add([]byte("2001:db8::1"), uint16(8443))
	f.Add([]byte("bad.example\r\nInjected: yes"), uint16(443))
	f.Add([]byte("host;curl attacker"), uint16(443))
	f.Fuzz(func(t *testing.T, hostBytes []byte, rawPort uint16) {
		if len(hostBytes) > 1<<12 {
			t.Skip()
		}
		port := int(rawPort)
		if port == 0 {
			port = 443
		}
		host := string(hostBytes)
		body := hostPolicyBody(Target{Host: host, Port: port})
		if strings.Contains(body, "\r") {
			t.Fatalf("deny body contains carriage return: %q", body)
		}
		marker := "cove allow "
		idx := strings.Index(body, marker)
		if idx < 0 {
			if !strings.Contains(body, "cove explain last") {
				t.Fatalf("invalid host did not use safe fallback body: %q", body)
			}
			return
		}
		command := body[idx+len(marker):]
		if end := strings.IndexByte(command, '\n'); end >= 0 {
			command = command[:end]
		}
		if command == "" || strings.ContainsAny(command, " \t\r\n;&|`$<>(){}'\"") {
			t.Fatalf("deny body emitted injectable shell text %q", command)
		}
		rule, err := config.ParseExactRule(command)
		if err != nil {
			t.Fatalf("deny body emitted an invalid allow target %q: %v", command, err)
		}
		if rule.Host != strings.ToLower(host) || rule.Port != port {
			t.Fatalf("rendered target changed destination: host=%q port=%d command=%q", host, port, command)
		}
		parsed, err := parseTarget(net.JoinHostPort(host, strconv.Itoa(port)))
		if err != nil || parsed.Host != rule.Host || parsed.Port != rule.Port {
			t.Fatalf("CONNECT validation disagrees with body rendering: parsed=%+v err=%v rule=%+v", parsed, err, rule)
		}
	})
}

func TestHostPolicyBodyRejectsHostWhitespace(t *testing.T) {
	body := hostPolicyBody(Target{Host: " api.example.com", Port: 443})
	if strings.Contains(body, "cove allow") || !strings.Contains(body, "cove explain last") {
		t.Fatalf("host whitespace produced copyable allow text: %q", body)
	}
}
