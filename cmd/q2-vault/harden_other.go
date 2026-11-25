//go:build !linux

package main

// harden does nothing off Linux: the Vault runs only on the Q2.
func harden() error { return nil }
