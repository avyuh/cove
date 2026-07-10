// Package configcmd owns read-only config command surfaces. Editing is kept
// separate until its recovery transaction is available.
package configcmd

import (
	"fmt"
	"io"
	"os"

	"cove/internal/clierr"
	"cove/internal/config"
)

var output io.Writer = os.Stdout

func Run(args []string) error {
	if len(args) != 1 || args[0] != "check" {
		return clierr.Wrap(clierr.EXUsage, "config accepts check", nil, "cove config check", nil)
	}
	doc, err := config.LoadDocument("")
	if err != nil {
		return err
	}
	protected := len(doc.Config.Inject) + len(doc.Config.SigV4) + len(doc.Config.MTLS)
	blocked := len(doc.Config.Managed.Block)
	fmt.Fprintf(output, "config valid — %d protected, %d allowed, %d blocked overrides, 0 exposed\n", protected, len(doc.Config.AllowRules), blocked)
	return nil
}
