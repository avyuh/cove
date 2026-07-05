package box

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strconv"
	"syscall"
	"time"
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
	agent, err := resolveAgentPath(d.AgentArgv[0], env)
	if err != nil {
		return 0, err
	}
	ctl := controlFile()
	if ctl != nil {
		applyInitialWinsize(master, ctl, 200*time.Millisecond)
		go readWinsize(master, ctl)
	}
	proc, err := startAgentChild(agent, d.AgentArgv[1:], env, statusFD, root, slavePath, ctl, master)
	if err != nil {
		return 0, err
	}
	forwardSignals(proc.Pid)
	go func() {
		_, _ = io.Copy(master, os.Stdin)
	}()
	go func() {
		_, _ = io.Copy(os.Stdout, master)
	}()
	code := waitForPID(proc.Pid)
	_ = proc.Release()
	_ = master.Close()
	return code, nil
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

func controlFile() *os.File {
	fd, err := strconv.Atoi(os.Getenv("COVE_CTL_FD"))
	if err != nil || fd <= 0 {
		return nil
	}
	f := os.NewFile(uintptr(fd), "cove-ctl")
	if f == nil {
		return nil
	}
	return f
}

func applyInitialWinsize(master *os.File, ctl *os.File, timeout time.Duration) {
	fd := int(ctl.Fd())
	_ = syscall.SetNonblock(fd, true)
	defer syscall.SetNonblock(fd, false)
	deadline := time.Now().Add(timeout)
	var buf [8]byte
	for {
		n, err := syscall.Read(fd, buf[:])
		if n == len(buf) {
			applyWinsize(master, buf[:])
			return
		}
		if err != syscall.EAGAIN && err != syscall.EWOULDBLOCK && err != syscall.EINTR {
			return
		}
		if time.Now().After(deadline) {
			return
		}
		time.Sleep(time.Millisecond)
	}
}

func readWinsize(master *os.File, ctl *os.File) {
	buf := make([]byte, 8)
	for {
		if _, err := io.ReadFull(ctl, buf); err != nil {
			return
		}
		applyWinsize(master, buf)
	}
}

func applyWinsize(master *os.File, buf []byte) {
	ws := winsize{
		Rows: binary.LittleEndian.Uint16(buf[0:2]),
		Cols: binary.LittleEndian.Uint16(buf[2:4]),
		X:    binary.LittleEndian.Uint16(buf[4:6]),
		Y:    binary.LittleEndian.Uint16(buf[6:8]),
	}
	if ws.Rows == 0 || ws.Cols == 0 {
		return
	}
	_, _, _ = syscall.Syscall(syscall.SYS_IOCTL, master.Fd(), syscall.TIOCSWINSZ, uintptr(unsafe.Pointer(&ws)))
}

func (w winsize) String() string {
	return fmt.Sprintf("%dx%d", w.Rows, w.Cols)
}
