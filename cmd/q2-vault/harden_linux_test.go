//go:build linux

package main

import (
	"syscall"
	"testing"
)

func TestHarden(t *testing.T) {
	if err := harden(); err != nil {
		t.Fatal(err)
	}
	d, _, e := syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_GET_DUMPABLE, 0, 0)
	if e != 0 || d != 0 {
		t.Fatalf("dumpable %d (%v)", d, e)
	}
	var rl syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &rl); err != nil || rl.Cur != 0 || rl.Max != 0 {
		t.Fatalf("core limit %+v (%v)", rl, err)
	}
}
