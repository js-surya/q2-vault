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

// SystemID is Q2 Pod's own id: the firmware's program, systemExe, run as root, asks as it (its
// scrobbling logins). No card app can have it: its folder .q2pod is refused.
const SystemID = "q2pod"

// systemExe is Q2 Pod's program, on the read-only system partition; a variable for tests.
var systemExe = "/release/bin/demo"

// AppID names the card app running as pid: its /proc/<pid>/exe must be
// exactly /mnt/mmc/.<id>/q2-<id> with the same valid id twice. The Vault's
// own binary and everything else is an error. Q2 Pod's own program, systemExe, is SystemID
// when uid, the caller's at connect from the kernel (SO_PEERCRED), is root.
func AppID(procRoot string, pid, uid int) (string, error) {
	exe, err := os.Readlink(filepath.Join(procRoot, strconv.Itoa(pid), "exe"))
	if err != nil {
		return "", err
	}
	orig := exe
	deleted := strings.HasSuffix(exe, " (deleted)")
	exe = strings.TrimSuffix(exe, " (deleted)") // updated while running
	var dir, want string
	if exe == systemExe {
		// Q2 Pod itself: root, and never a deleted binary (the system partition is read-only, so a
		// deleted one isn't Q2 Pod's).
		if deleted || uid != 0 { /* uid: the kernel's, at connect (SO_PEERCRED) */
			return "", errors.New("proto: not Q2 Pod")
		}
		dir, want = SystemID, systemExe
	} else {
		rest, ok := strings.CutPrefix(exe, cardRoot+"/.")
		if !ok {
			return "", errors.New("proto: not a card app")
		}
		var file string
		dir, file, ok = strings.Cut(rest, "/")
		if !ok || !idRe.MatchString(dir) || dir == "vault" || dir == SystemID || file != "q2-"+dir {
			return "", errors.New("proto: not a card app")
		}
		want = cardRoot + "/." + dir + "/q2-" + dir
	}
	// The path alone can be faked from a private mount namespace (an app
	// mounting its own file there). (a) Same mount namespace as the Vault, if
	// the kernel shows them; (b) the running inode is the real card file.
	ours, e2 := os.Readlink(selfNS)
	if e2 == nil { // else a kernel without ns files: the inode check below
		theirs, e1 := os.Readlink(filepath.Join(procRoot, strconv.Itoa(pid), "ns", "mnt"))
		if e1 != nil || theirs != ours { // fail closed: an unreadable peer is refused
			return "", errors.New("proto: other or unreadable mount namespace")
		}
	}
	// The pid must not have been replaced while we looked.
	if again, err := os.Readlink(filepath.Join(procRoot, strconv.Itoa(pid), "exe")); err != nil || again != orig {
		return "", errors.New("proto: caller changed while checked")
	}
	if !deleted {
		got, err := exeStat(filepath.Join(procRoot, strconv.Itoa(pid), "exe"))
		if err != nil {
			return "", err
		}
		w, err := os.Stat(want)
		if err != nil || !os.SameFile(got, w) {
			return "", errors.New("proto: not the card binary")
		}
	}
	return dir, nil
}
