//go:build !linux

package vault

import "net"

// osPeerUID: the Vault runs only on the Q2 (Linux). Elsewhere there is no
// Vault to impersonate, so development builds and tests proceed; tests
// replace peerUID to simulate root and non-root servers.
func osPeerUID(*net.UnixConn) (uint32, error) { return 0, nil }
