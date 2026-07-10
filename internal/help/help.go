// Package help renders cove's public command help without exposing proxy
// implementation roles.
package help

import (
	"fmt"
	"os"

	"cove/internal/clierr"
)

// Run prints top-level help or help for one exact public command.
func Run(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stdout, topLevel)
		return nil
	}
	if len(args) != 1 {
		return clierr.Wrap(clierr.EXUsage, "help accepts one command", nil, "cove help", nil)
	}
	text, ok := commandHelp[args[0]]
	if !ok {
		return clierr.Wrap(clierr.EXUsage, "unknown command "+args[0], nil, "cove help", nil)
	}
	fmt.Fprint(os.Stdout, text)
	return nil
}

const topLevel = `cove is the doorman who only opens the door to hosts you allow and stamps your real keys on at the door.

usage:
  cove <agent> [args...]
  cove [flags] -- <agent> [args...]

The first form runs an agent in a contained session. Use -- when an agent name
collides with a cove command, such as: cove -- log.

Daily commands:
  cove setup                 prepare this machine for contained sessions
  cove status                check readiness (doctor is an alias)
  cove add <service>         add a protected connection
  cove allow <host>          make a host reachable
  cove remove <name>         remove a managed connection
  cove list                  show configured connections
  cove log                   read audit records

Config commands:
  cove config check          validate the policy
  cove config edit           edit the policy

Diagnostic commands:
  cove sessions              list recent sessions
  cove explain last          explain the latest blocked request
  cove help [command]        show command help

Launcher flags:
  -C, --project DIR          project mounted at /work (default: cwd)
      --no-audit             disable audit for this run
  -v, --verbose              print launcher diagnostics
      --dry-run              print launch plan and exit
  -h, --help                 show this help
      --version              show version

Verdicts: protected / allowed / blocked correspond to inject / allow / deny in
machine-readable configuration and JSONL.

Exit codes: 64 usage, 66 input, 69 unavailable, 73 create, 74 I/O,
75 temporary, 77 permission, 78 config, 126 cannot execute, 127 not found.
`

var commandHelp = map[string]string{
	"setup":    "usage: cove setup\n\nPrepare this machine for contained sessions.\n",
	"status":   "usage: cove status [--verbose]\n\nCheck whether cove is ready.\n",
	"add":      "usage: cove add <service> [flags]\n\nAdd a protected connection.\n",
	"allow":    "usage: cove allow <host> [--once] [--yes]\n\nMake a host reachable.\n",
	"remove":   "usage: cove remove <name>\n\nRemove a managed connection.\n",
	"list":     "usage: cove list\n\nShow configured connections.\n",
	"log":      "usage: cove log [--follow] [--session ID] [--host HOST] [--deny-only]\n\nRead audit records.\n",
	"config":   "usage: cove config <check|edit>\n\nValidate or edit the policy.\n",
	"sessions": "usage: cove sessions\n\nList recent sessions.\n",
	"explain":  "usage: cove explain last\n\nExplain the latest blocked request.\n",
	"help":     "usage: cove help [command]\n\nShow cove command help.\n",
}
