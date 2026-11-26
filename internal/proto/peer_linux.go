//go:build linux

package proto

import (
	"net"
	"syscall"
)

// peerPIDOS reads the caller's pid and uid from the kernel (SO_PEERCRED), as they were at connect.
func peerPIDOS(c *net.UnixConn) (int, int, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var cred *syscall.Ucred
	var serr error
	if err := raw.Control(func(fd uintptr) {
		cred, serr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return 0, 0, err
	}
	if serr != nil {
		return 0, 0, serr
	}
	return int(cred.Pid), int(cred.Uid), nil
}
