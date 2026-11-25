package proto

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// cardRoot is where card apps live; a variable so tests can use a temp dir.
var cardRoot = "/mnt/mmc"

// selfNS is this process's mount namespace link.
var selfNS = "/proc/self/ns/mnt"

// exeStat follows /proc/<pid>/exe's magic link to the real inode.
var exeStat = os.Stat

var idRe = regexp.MustCompile(`^[a-z0-9-]{1,15}$`)

// AppID names the card app running as pid: its /proc/<pid>/exe must be
// exactly /mnt/mmc/.<id>/q2-<id> with the same valid id twice. The Vault's
// own binary and everything else is an error.
func AppID(procRoot string, pid int) (string, error) {
	exe, err := os.Readlink(filepath.Join(procRoot, strconv.Itoa(pid), "exe"))
	if err != nil {
		return "", err
	}
	deleted := strings.HasSuffix(exe, " (deleted)")
	exe = strings.TrimSuffix(exe, " (deleted)") // updated while running
	rest, ok := strings.CutPrefix(exe, cardRoot+"/.")
	if !ok {
		return "", errors.New("proto: not a card app")
	}
	dir, file, ok := strings.Cut(rest, "/")
	if !ok || !idRe.MatchString(dir) || dir == "vault" || file != "q2-"+dir {
		return "", errors.New("proto: not a card app")
	}
	// The path alone can be faked from a private mount namespace (an app
	// mounting its own file there). (a) Same mount namespace as the Vault, if
	// the kernel shows them; (b) the running inode is the real card file.
	theirs, e1 := os.Readlink(filepath.Join(procRoot, strconv.Itoa(pid), "ns", "mnt"))
	ours, e2 := os.Readlink(selfNS)
	if e1 == nil && e2 == nil && theirs != ours {
		return "", errors.New("proto: other mount namespace")
	}
	if !deleted {
		got, err := exeStat(filepath.Join(procRoot, strconv.Itoa(pid), "exe"))
		if err != nil {
			return "", err
		}
		want, err := os.Stat(cardRoot + "/." + dir + "/q2-" + dir)
		if err != nil || !os.SameFile(got, want) {
			return "", errors.New("proto: not the card binary")
		}
	}
	return dir, nil
}
