package box

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

const (
	sioCGIFFLAGS = 0x8913
	sioCSIFFLAGS = 0x8914
	iffUP        = 0x1
	iffRUNNING   = 0x40
)

type ifreqFlags struct {
	Name  [16]byte
	Flags int16
	Pad   [22]byte
}

func bringLoopbackUp() error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	var ifr ifreqFlags
	copy(ifr.Name[:], "lo")
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), sioCGIFFLAGS, uintptr(unsafe.Pointer(&ifr))); errno != 0 {
		return errno
	}
	ifr.Flags |= iffUP | iffRUNNING
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), sioCSIFFLAGS, uintptr(unsafe.Pointer(&ifr))); errno != 0 {
		return errno
	}
	return nil
}

func startShim(port int) error {
	ln, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return err
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go shimConn(c)
		}
	}()
	return nil
}

func shimConn(c net.Conn) {
	defer c.Close()
	u, err := net.Dial("unix", "/proxy/proxy.sock")
	if err != nil {
		return
	}
	defer u.Close()
	done := make(chan struct{}, 2)
	go func() {
		_, _ = ioCopy(u, c)
		done <- struct{}{}
	}()
	go func() {
		_, _ = ioCopy(c, u)
		done <- struct{}{}
	}()
	<-done
}

func ioCopy(dst net.Conn, src net.Conn) (int64, error) {
	buf := make([]byte, 32*1024)
	var total int64
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			total += int64(n)
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return total, werr
			}
		}
		if rerr != nil {
			return total, rerr
		}
	}
}

func dropCaps() error {
	const (
		prSetNoNewPrivs = 38
		prCapBsetDrop   = 24
		capVersion3     = 0x20080522
	)
	if _, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, prSetNoNewPrivs, 1, 0, 0, 0, 0); errno != 0 {
		return errno
	}
	for cap := uintptr(0); cap < 64; cap++ {
		_, _, _ = syscall.Syscall6(syscall.SYS_PRCTL, prCapBsetDrop, cap, 0, 0, 0, 0)
	}
	type capHeader struct {
		Version uint32
		PID     int32
	}
	type capData struct {
		Effective   uint32
		Permitted   uint32
		Inheritable uint32
	}
	hdr := capHeader{Version: capVersion3}
	data := [2]capData{}
	if _, _, errno := syscall.Syscall(syscall.SYS_CAPSET, uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data[0])), 0); errno != 0 {
		return errno
	}
	return nil
}
