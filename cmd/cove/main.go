package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"cove/internal/box"
	"cove/internal/config"
	"cove/internal/launcher"
	"cove/internal/logcmd"
	"cove/internal/proxy"
	"cove/internal/setup"
	"cove/internal/version"
)

func main() {
	os.Exit(run(os.Args))
}

func run(args []string) int {
	if len(args) == 0 {
		args = []string{"cove"}
	}
	switch detectRole(args) {
	case "proxyd":
		return proxydMain(args[2:])
	case "__init":
		return box.InitMain()
	case "__agent":
		return box.AgentMain(args[2:])
	case "__apparmor":
		return exitFor(setup.ApparmorOnly())
	case "__probe_userns":
		return exitFor(setup.ProbeUsernsSelf())
	case "setup":
		return exitFor(setup.Run(args[2:]))
	case "log":
		return exitFor(logcmd.Run(args[2:]))
	default:
		return launcherMain(args[1:])
	}
}

func detectRole(args []string) string {
	if len(args) < 2 {
		return "launcher"
	}
	switch args[1] {
	case "proxyd", "__init", "__agent", "__apparmor", "__probe_userns", "setup", "log":
		return args[1]
	default:
		return "launcher"
	}
}

func launcherMain(args []string) int {
	fs := flag.NewFlagSet("cove", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	project := fs.String("project", ".", "project directory mounted at /work")
	fs.StringVar(project, "C", ".", "project directory mounted at /work")
	noAudit := fs.Bool("no-audit", false, "disable audit for this run")
	verbose := fs.Bool("verbose", false, "print launcher diagnostics")
	fs.BoolVar(verbose, "v", false, "print launcher diagnostics")
	dryRun := fs.Bool("dry-run", false, "print launch plan and exit")
	help := fs.Bool("help", false, "show help")
	fs.BoolVar(help, "h", false, "show help")
	versionFlag := fs.Bool("version", false, "show version")
	fs.Usage = usage

	split := -1
	for i, arg := range args {
		if arg == "--" {
			split = i
			break
		}
	}
	flagArgs := args
	agentArgs := []string(nil)
	if split >= 0 {
		flagArgs = args[:split]
		agentArgs = args[split+1:]
	}
	if err := fs.Parse(flagArgs); err != nil {
		return 64
	}
	if *help {
		usage()
		return 0
	}
	if *versionFlag {
		fmt.Printf("cove %s\n", version.Version)
		return 0
	}
	if split < 0 {
		usage()
		return 64
	}
	if len(agentArgs) == 0 {
		fmt.Fprintln(os.Stderr, "cove: missing agent after --")
		return 64
	}

	cfg, err := config.Load("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "cove: config: %v\n", err)
		return 78
	}
	code, err := launcher.Run(cfg, launcher.Opts{
		Project:   *project,
		NoAudit:   *noAudit,
		Verbose:   *verbose,
		DryRun:    *dryRun,
		AgentArgv: agentArgs,
		Version:   version.Version,
	})
	if err != nil {
		var exitErr launcher.ExitError
		if errors.As(err, &exitErr) {
			fmt.Fprintln(os.Stderr, exitErr.Error())
			return exitErr.Code
		}
		fmt.Fprintf(os.Stderr, "cove: %v\n", err)
		return code
	}
	return code
}

func proxydMain(args []string) int {
	fs := flag.NewFlagSet("cove proxyd", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	help := fs.Bool("help", false, "show help")
	if err := fs.Parse(args); err != nil {
		return 64
	}
	if *help {
		fmt.Fprintln(os.Stderr, "usage: cove proxyd")
		return 0
	}
	cfg, err := config.Load("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "cove proxyd: config: %v\n", err)
		return 78
	}
	if err := proxy.Serve(cfg, ""); err != nil {
		fmt.Fprintf(os.Stderr, "cove proxyd: %v\n", err)
		return 69
	}
	return 0
}

func exitFor(err error) int {
	if err == nil {
		return 0
	}
	var coded interface{ ExitCode() int }
	if errors.As(err, &coded) {
		fmt.Fprintln(os.Stderr, err)
		return coded.ExitCode()
	}
	fmt.Fprintln(os.Stderr, err)
	return 1
}

func usage() {
	fmt.Fprintf(os.Stderr, `usage:
  cove [flags] -- <agent> [args...]
  cove setup
  cove proxyd
  cove log [--follow] [--session ID] [--host HOST] [--deny-only]

flags:
  -C, --project DIR   project mounted at /work (default: cwd)
      --no-audit      disable audit for this run
  -v, --verbose       print launcher diagnostics
      --dry-run       print launch plan and exit
      --version       show version
`)
}
