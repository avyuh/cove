package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"cove/internal/box"
	"cove/internal/clierr"
	"cove/internal/config"
	"cove/internal/configcmd"
	"cove/internal/connection"
	"cove/internal/explain"
	"cove/internal/help"
	"cove/internal/launcher"
	"cove/internal/logcmd"
	"cove/internal/proxy"
	"cove/internal/sessioncmd"
	"cove/internal/setup"
	"cove/internal/status"
	"cove/internal/version"
)

const (
	invocationLauncher = "launcher"
	invocationCommand  = "command"
	invocationInternal = "internal"
)

// Invocation is the result of the ordered command-line grammar. AgentArgv is
// always a slice of the process argv; it is never reconstructed from text.
type Invocation struct {
	Kind      string
	Name      string
	Args      []string
	AgentArgv []string
	Project   string
	NoAudit   bool
	Verbose   bool
	DryRun    bool
	Help      bool
	Version   bool
}

func main() {
	os.Exit(run(os.Args))
}

func run(args []string) int {
	inv, err := parseInvocation(args)
	if err != nil {
		return clierr.Print(os.Stderr, err)
	}

	switch inv.Kind {
	case invocationInternal:
		return runInternal(inv)
	case invocationCommand:
		if inv.Name != "help" && len(inv.Args) == 1 && (inv.Args[0] == "--help" || inv.Args[0] == "-h") {
			return exitFor(help.Run([]string{inv.Name}))
		}
		return runPublic(inv)
	default:
		return launcherMain(inv)
	}
}

// parseInvocation implements the grammar in architecture §2.1. Keep its
// branches in the specified order: hidden roles, -- escape, public commands,
// then launcher flags and the first positional agent.
func parseInvocation(args []string) (Invocation, error) {
	if len(args) == 0 {
		args = []string{"cove"}
	}

	if len(args) > 1 {
		if isInternalRole(args[1]) {
			return Invocation{Kind: invocationInternal, Name: args[1], Args: args[2:]}, nil
		}
		if args[1] == "--" {
			if len(args) < 3 {
				return Invocation{}, usageError("missing agent after --")
			}
			return Invocation{Kind: invocationLauncher, AgentArgv: args[2:], Project: "."}, nil
		}
		if isPublicCommand(args[1]) || args[1] == "doctor" {
			name := args[1]
			if name == "doctor" {
				name = "status"
			}
			return Invocation{Kind: invocationCommand, Name: name, Args: args[2:]}, nil
		}
	}

	fs := flag.NewFlagSet("cove", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	project := fs.String("project", ".", "project directory mounted at /work")
	fs.StringVar(project, "C", ".", "project directory mounted at /work")
	noAudit := fs.Bool("no-audit", false, "disable audit for this run")
	verbose := fs.Bool("verbose", false, "print launcher diagnostics")
	fs.BoolVar(verbose, "v", false, "print launcher diagnostics")
	dryRun := fs.Bool("dry-run", false, "print launch plan and exit")
	helpFlag := fs.Bool("help", false, "show help")
	fs.BoolVar(helpFlag, "h", false, "show help")
	versionFlag := fs.Bool("version", false, "show version")
	if err := fs.Parse(args[1:]); err != nil {
		return Invocation{}, clierr.Wrap(clierr.EXUsage, "invalid launcher option", nil, "cove help", err)
	}
	inv := Invocation{
		Kind:      invocationLauncher,
		AgentArgv: fs.Args(),
		Project:   *project,
		NoAudit:   *noAudit,
		Verbose:   *verbose,
		DryRun:    *dryRun,
		Help:      *helpFlag,
		Version:   *versionFlag,
	}
	if inv.Help || inv.Version {
		return inv, nil
	}
	if len(inv.AgentArgv) == 0 {
		return Invocation{}, usageError("missing agent")
	}
	return inv, nil
}

func isInternalRole(name string) bool {
	switch name {
	case "proxyd", "__init", "__agent", "__apparmor", "__probe_userns", "__status_probe":
		return true
	default:
		return false
	}
}

func isPublicCommand(name string) bool {
	_, ok := public[name]
	return ok
}

var public = map[string]func([]string) error{
	"setup":    setup.Run,
	"status":   status.Run,
	"add":      connection.Add,
	"allow":    connection.Allow,
	"remove":   connection.Remove,
	"list":     connection.List,
	"log":      logcmd.Run,
	"config":   configcmd.Run,
	"sessions": sessioncmd.Run,
	"explain":  explain.Run,
	"help":     help.Run,
}

func runPublic(inv Invocation) int {
	return exitFor(public[inv.Name](inv.Args))
}

func unavailable(args []string) error {
	return clierr.Wrap(clierr.EXUsage, "command not available yet", nil, "cove help", nil)
}

func runInternal(inv Invocation) int {
	switch inv.Name {
	case "proxyd":
		return proxydMain(inv.Args)
	case "__init":
		return box.InitMain()
	case "__agent":
		return box.AgentMain(inv.Args)
	case "__apparmor":
		return exitFor(setup.ApparmorOnly())
	case "__probe_userns":
		return exitFor(setup.ProbeUsernsSelf())
	case "__status_probe":
		// The role is reserved for the contained status probe. It is intentionally
		// not a public command and carries no user input or credentials.
		return 0
	default:
		return clierr.Print(os.Stderr, usageError("unknown internal role"))
	}
}

func launcherMain(inv Invocation) int {
	if inv.Help {
		return exitFor(help.Run(nil))
	}
	if inv.Version {
		fmt.Printf("cove %s\n", version.Version)
		return 0
	}
	cfg, err := config.Load("")
	if err != nil {
		return clierr.Print(os.Stderr, err)
	}
	code, err := launcher.Run(cfg, launcher.Opts{
		Project:   inv.Project,
		NoAudit:   inv.NoAudit,
		Verbose:   inv.Verbose,
		DryRun:    inv.DryRun,
		AgentArgv: inv.AgentArgv,
		Version:   version.Version,
	})
	if err != nil {
		return clierr.Print(os.Stderr, err)
	}
	return code
}

func proxydMain(args []string) int {
	fs := flag.NewFlagSet("cove proxyd", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	helpFlag := fs.Bool("help", false, "show help")
	if err := fs.Parse(args); err != nil {
		return clierr.Print(os.Stderr, clierr.Wrap(clierr.EXUsage, "invalid proxy option", nil, "cove help", err))
	}
	if *helpFlag {
		// proxyd is deliberately callable but not part of the public help surface.
		fmt.Fprintln(os.Stderr, "usage: cove proxyd")
		return 0
	}
	cfg, err := config.Load("")
	if err != nil {
		return clierr.Print(os.Stderr, err)
	}
	if err := proxy.Serve(cfg, ""); err != nil {
		return clierr.Print(os.Stderr, clierr.Wrap(clierr.EXUnavailable, "proxy unavailable", nil, "cove status", err))
	}
	return 0
}

func usageError(what string) error {
	return clierr.Wrap(clierr.EXUsage, what, nil, "cove help", nil)
}

func exitFor(err error) int {
	if err == nil {
		return 0
	}
	return clierr.Print(os.Stderr, err)
}
