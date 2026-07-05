package box

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"unsafe"
)

type winsize struct {
	Rows uint16
	Cols uint16
	X    uint16
	Y    uint16
}

func runAgentPTY(d Directives, env []string, statusFD int, root string) (int, error) {
	master, slavePath, err := openPTY()
	if err != nil {
		return 0, err
	}
	defer master.Close()
	slave, err := os.OpenFile(slavePath, os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return 0, err
	}
	cmd := exec.Command(d.AgentArgv[0], d.AgentArgv[1:]...)
	cmd.Env = env
	cmd.Stdin = slave
	cmd.Stdout = slave
	cmd.Stderr = slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		_ = slave.Close()
		return 0, err
	}
	_ = slave.Close()
	writeStatus(statusFD, "OK "+root)
	forwardSignals(cmd.Process.Pid)
	go func() {
		_, _ = io.Copy(master, os.NewFile(0, "stdin"))
	}()
	go func() {
		_, _ = io.Copy(os.NewFile(1, "stdout"), master)
	}()
	go readWinsize(master)
	return waitForPID(cmd.Process.Pid), nil
}

func openPTY() (*os.File, string, error) {
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, "", err
	}
	var unlock int32
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, master.Fd(), syscall.TIOCSPTLCK, uintptr(unsafe.Pointer(&unlock))); errno != 0 {
		_ = master.Close()
		return nil, "", errno
	}
	var n uint32
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, master.Fd(), syscall.TIOCGPTN, uintptr(unsafe.Pointer(&n))); errno != 0 {
		_ = master.Close()
		return nil, "", errno
	}
	return master, "/dev/pts/" + strconv.Itoa(int(n)), nil
}

func readWinsize(master *os.File) {
	fd, err := strconv.Atoi(os.Getenv("COVE_CTL_FD"))
	if err != nil || fd <= 0 {
		return
	}
	f := os.NewFile(uintptr(fd), "cove-ctl")
	if f == nil {
		return
	}
	buf := make([]byte, 8)
	for {
		if _, err := io.ReadFull(f, buf); err != nil {
			return
		}
		ws := winsize{
			Rows: binary.LittleEndian.Uint16(buf[0:2]),
			Cols: binary.LittleEndian.Uint16(buf[2:4]),
			X:    binary.LittleEndian.Uint16(buf[4:6]),
			Y:    binary.LittleEndian.Uint16(buf[6:8]),
		}
		if ws.Rows == 0 || ws.Cols == 0 {
			continue
		}
		_, _, _ = syscall.Syscall(syscall.SYS_IOCTL, master.Fd(), syscall.TIOCSWINSZ, uintptr(unsafe.Pointer(&ws)))
	}
}

func (w winsize) String() string {
	return fmt.Sprintf("%dx%d", w.Rows, w.Cols)
}
