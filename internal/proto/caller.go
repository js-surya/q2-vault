package proto

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var idRe = regexp.MustCompile(`^[a-z0-9-]{1,15}$`)

// AppID names the card app running as pid: its /proc/<pid>/exe must be
// exactly /mnt/mmc/.<id>/q2-<id> with the same valid id twice. The Vault's
// own binary and everything else is an error.
func AppID(procRoot string, pid int) (string, error) {
	exe, err := os.Readlink(filepath.Join(procRoot, strconv.Itoa(pid), "exe"))
	if err != nil {
		return "", err
	}
	exe = strings.TrimSuffix(exe, " (deleted)") // updated while running
	rest, ok := strings.CutPrefix(exe, "/mnt/mmc/.")
	if !ok {
		return "", errors.New("proto: not a card app")
	}
	dir, file, ok := strings.Cut(rest, "/")
	if !ok || !idRe.MatchString(dir) || dir == "vault" || file != "q2-"+dir {
		return "", errors.New("proto: not a card app")
	}
	return dir, nil
}
