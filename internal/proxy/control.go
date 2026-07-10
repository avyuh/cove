package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"regexp"
	"sort"
	"sync"

	"cove/internal/config"
)

const controlLineLimit = 64 << 10

var sessionIDRE = regexp.MustCompile(`^[0-9a-f]+$`)

// RegisterRequest is deliberately a new, versioned protocol.  Do not add these
// fields to REGISTER: old daemons silently ignore trailing whitespace fields.
type RegisterRequest struct {
	Session string `json:"session"`
	Agent   string `json:"agent"`
	Audit   *bool  `json:"audit"`
	Project string `json:"project"`
}

type controlOK struct {
	Socket  string `json:"socket"`
	Session string `json:"session"`
}
type controlEvent struct {
	Type   string `json:"type"`
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Status int    `json:"status"`
	Reason string `json:"reason"`
}
type denyCount struct {
	Host  string `json:"host"`
	Port  int    `json:"port"`
	Count int    `json:"count"`
}
type controlEnd struct {
	Denies        []denyCount `json:"denies"`
	DroppedEvents uint64      `json:"dropped_events"`
}

func decodeRegister(line string) (RegisterRequest, error) {
	var r RegisterRequest
	d := json.NewDecoder(io.LimitReader(&stringReader{s: line}, controlLineLimit))
	d.DisallowUnknownFields()
	if err := d.Decode(&r); err != nil {
		return r, err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return r, fmt.Errorf("multiple JSON values")
	}
	if r.Audit == nil || !sessionIDRE.MatchString(r.Session) || r.Agent == "" || len([]byte(r.Agent)) > 128 {
		return r, fmt.Errorf("invalid REGISTER/2")
	}
	return r, nil
}

// stringReader avoids accepting a second JSON document while keeping decoding
// bounded by the protocol line limit.
type stringReader struct {
	s   string
	off int
}

func (r *stringReader) Read(p []byte) (int, error) {
	if r.off >= len(r.s) {
		return 0, io.EOF
	}
	n := copy(p, r.s[r.off:])
	r.off += n
	return n, nil
}

type sessionEventSink struct{ event controlEvent }

// SessionEvents is memory/control-plane only. RecordDeny updates the aggregate
// before attempting the bounded channel, so receipt counts are authoritative.
type SessionEvents struct {
	mu      sync.Mutex
	denies  map[string]*denyCount
	dropped uint64
	ch      chan sessionEventSink
	closed  bool
	end     *controlEnd
}

func NewSessionEvents() *SessionEvents {
	return &SessionEvents{denies: make(map[string]*denyCount), ch: make(chan sessionEventSink, 128)}
}

func (s *SessionEvents) RecordDeny(rec *AuditRecord) {
	if s == nil {
		return
	}
	k := fmt.Sprintf("%s\x00%d", rec.Host, rec.Port)
	s.mu.Lock()
	d := s.denies[k]
	if d == nil {
		d = &denyCount{Host: rec.Host, Port: rec.Port}
		s.denies[k] = d
	}
	d.Count++
	if s.closed {
		s.mu.Unlock()
		return
	}
	e := sessionEventSink{event: controlEvent{Type: "deny", Host: rec.Host, Port: rec.Port, Status: rec.Status, Reason: rec.Reason}}
	select {
	case s.ch <- e:
	default:
		s.dropped++
	}
	s.mu.Unlock()
}

func (s *SessionEvents) close(withEnd bool) <-chan sessionEventSink {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		close(s.ch)
	}
	denies := make([]denyCount, 0, len(s.denies))
	for _, d := range s.denies {
		denies = append(denies, *d)
	}
	sort.Slice(denies, func(i, j int) bool {
		if denies[i].Host == denies[j].Host {
			return denies[i].Port < denies[j].Port
		}
		return denies[i].Host < denies[j].Host
	})
	if withEnd {
		s.end = &controlEnd{Denies: denies, DroppedEvents: s.dropped}
	}
	return s.ch
}

func (s *SessionEvents) endMessage() *controlEnd { s.mu.Lock(); defer s.mu.Unlock(); return s.end }

func controlJSON(prefix string, v any) string {
	b, _ := json.Marshal(v)
	return prefix + " " + string(b) + "\n"
}

// WithAllows returns an immutable overlay. Claims can only add allow rules;
// existing protected/exact rules continue to win by matcher ordering.
func (m *Matcher) WithAllows(claimed []config.AllowRule) *Matcher {
	n := &Matcher{rules: append([]compiledRule(nil), m.rules...)}
	for _, r := range claimed {
		n.rules = append(n.rules, compiledRule{rule: r, policy: PolicyAllow})
	}
	return n
}

func closeRaw(conns map[net.Conn]struct{}) {
	for c := range conns {
		_ = c.Close()
	}
}
