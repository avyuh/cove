package proxy

import (
	"errors"
	"fmt"

	"cove/internal/config"
)

type Policy int

const (
	PolicyDeny Policy = iota
	PolicyAllow
	PolicyInject
)

type Session struct {
	ID    string
	Agent string
}

func Serve(cfg *config.Config, sockPath string) error {
	return fmt.Errorf("proxy not implemented before M3 (rules=%d sock=%q)", len(cfg.AllowRules), sockPath)
}

var ErrDenied = errors.New("denied by policy")
