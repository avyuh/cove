package launcher

import (
	"fmt"

	"cove/internal/config"
)

type Opts struct {
	Project   string
	NoAudit   bool
	Verbose   bool
	DryRun    bool
	AgentArgv []string
	Version   string
}

type ExitError struct {
	Code int
	Msg  string
}

func (e ExitError) Error() string {
	return e.Msg
}

func Run(cfg *config.Config, opts Opts) (int, error) {
	if opts.DryRun {
		fmt.Printf("project=%s proxy_port=%d agent=%q\n", opts.Project, cfg.Options.ProxyPort, opts.AgentArgv)
		return 0, nil
	}
	return 69, ExitError{Code: 69, Msg: "cove: launcher not implemented before M2"}
}
