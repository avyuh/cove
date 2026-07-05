package box

import (
	"fmt"
	"os"
)

func InitMain() int {
	if os.Getenv("COVE_PROBE_USERNS") == "1" {
		return 0
	}
	fmt.Fprintln(os.Stderr, "cove __init: not implemented before M2")
	return 75
}
