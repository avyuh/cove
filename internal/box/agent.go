package box

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

const (
	agentDirFD       = 3
	agentStatusFD    = 4
	agentCtlFD       = 5
	agentPTYMasterFD = 6

	agentTrampolinePath = "/.cove-agent"
)

func AgentMain(args []string) int {
	if len(args) < 4 {
		writeStatus(agentStatusFD, "ERR agent-bootstrap malformed")
		closeAgentFiles(-1)
		return 75
	}
	root := args[0]
	slavePath := args[1]
	masterFD, err := strconv.Atoi(args[2])
	if err != nil {
		masterFD = -1
	}
	agent := args[3]
	agentArgv := args[3:]

	if slavePath != "-" {
		if err := setupChildTTY(slavePath); err != nil {
			writeStatus(agentStatusFD, "ERR pty-child "+err.Error())
			closeAgentFiles(masterFD)
			return 75
		}
	}
	if err := dropCaps(); err != nil {
		writeStatus(agentStatusFD, "ERR agent-privdrop "+err.Error())
		closeAgentFiles(masterFD)
		return 75
	}

	writeStatus(agentStatusFD, "OK "+root)
	closeAgentFiles(masterFD)
	if err := syscall.Exec(agent, agentArgv, scrubAgentEnv(os.Environ())); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "cove-agent: exec %s: %v\n", agent, err)
		if agentNotFound(err) {
			return 127
		}
		return 126
	}
	return 126
}

func setupChildTTY(slavePath string) error {
	slave, err := os.OpenFile(slavePath, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	slaveFD := int(slave.Fd())
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, slave.Fd(), syscall.TIOCSCTTY, 1); errno != 0 {
		_ = slave.Close()
		return errno
	}
	pgrp := syscall.Getpgrp()
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, slave.Fd(), syscall.TIOCSPGRP, uintptr(unsafe.Pointer(&pgrp))); errno != 0 {
		_ = slave.Close()
		return errno
	}
	for _, fd := range []int{0, 1, 2} {
		if slaveFD == fd {
			continue
		}
		if err := syscall.Dup3(slaveFD, fd, 0); err != nil {
			_ = slave.Close()
			return err
		}
	}
	if slaveFD > 2 {
		_ = slave.Close()
	}
	return nil
}

func closeAgentFiles(masterFD int) {
	for _, fd := range []int{agentDirFD, agentStatusFD, agentCtlFD, masterFD} {
		if fd >= 0 {
			_ = syscall.Close(fd)
		}
	}
}

func scrubAgentEnv(env []string) []string {
	out := env[:0]
	for _, kv := range env {
		name, _, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		switch name {
		case "COVE_DIR_FD", "COVE_STATUS_FD", "COVE_CTL_FD", "COVE_TERM":
			continue
		}
		out = append(out, kv)
	}
	return out
}
