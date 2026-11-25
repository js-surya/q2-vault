//go:build linux

package main

import "syscall"

// harden keeps the master key out of reach of other processes' ptrace and /proc/<pid>/mem (not
// dumpable), and out of core files (none written).
func harden() error {
	if _, _, e := syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_SET_DUMPABLE, 0, 0); e != 0 {
		return e
	}
	return syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0})
}
