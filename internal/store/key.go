// Package store keeps the master key file and the sealed logins on the card.
package store

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// writeAtomic writes data to path as tmp + fsync + rename, then syncs the folder with syncFolder
// (syncDir in internal storage, syncCardDir on the card).
func writeAtomic(path string, data []byte, mode os.FileMode, syncFolder func(string) error) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	return syncFolder(filepath.Dir(path))
}

// dirSync fsyncs a folder; a hook so tests can make it fail.
var dirSync = func(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// syncDir fsyncs a folder in internal storage: every error counts.
func syncDir(dir string) error { return dirSync(dir) }

// syncCardDir fsyncs the card's folder of sealed logins. exFAT's driver may refuse a folder fsync
// (EINVAL, ENOTSUP); the file itself was fsynced before its rename, so that refusal is let pass.
// Every other error counts.
func syncCardDir(dir string) error {
	err := dirSync(dir)
	if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOTSUP) {
		return nil
	}
	return err
}

// LoadOrCreateKey reads dir/key (exactly 32 bytes) or makes it from rand.
func LoadOrCreateKey(dir string, rand io.Reader) ([32]byte, error) {
	var k [32]byte
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return k, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return k, err
	}
	path := filepath.Join(dir, "key")
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		if len(b) != len(k) {
			return k, fmt.Errorf("store: key file is %d bytes, want 32", len(b))
		}
		copy(k[:], b)
		if k == [32]byte{} {
			return [32]byte{}, errors.New("store: key file is all zero")
		}
		if err := os.Chmod(path, 0o600); err != nil {
			return [32]byte{}, err
		}
		return k, nil
	case !errors.Is(err, os.ErrNotExist):
		return k, err
	}
	if _, err := io.ReadFull(rand, k[:]); err != nil {
		return [32]byte{}, err
	}
	if err := writeAtomic(path, k[:], 0o600, syncDir); err != nil {
		return [32]byte{}, err
	}
	return k, nil
}
