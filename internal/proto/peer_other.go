//go:build !linux

package proto

import (
	"errors"
	"net"
)

// peerPIDOS has no peer credentials off Linux: every caller is refused.
func peerPIDOS(*net.UnixConn) (int, int, error) {
	return 0, 0, errors.New("proto: no peer credentials on this system")
}
