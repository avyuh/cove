package setup

import "fmt"

func Run(args []string) error {
	return fmt.Errorf("cove setup not implemented before M1")
}

func ApparmorOnly() error {
	return fmt.Errorf("cove __apparmor not implemented before M1")
}

func ProbeUsernsSelf() error {
	return nil
}
