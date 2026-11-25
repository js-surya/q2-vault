// Adapted from q2-tailscale's cmd/q2-tailscale/remove.go (same author, MIT).

package main

import (
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// removeScript outlives the app. The App Store's Remove stops the app, then deletes its card folder,
// but not the key it keeps in internal storage nor the sealed logins beside the app: so, after a stop,
// this watches the card folder for tries×gap seconds, and once it's gone with the card still mounted (a
// Remove, not the card taken out or handed to USB storage, which take the folder with them) deletes the
// key's folder and the sealed logins' folder too.
//
// A card pulled during the watch can make the app folder look gone while /proc/mounts still lists the
// card, so every condition must hold at once: the card still readable, the sealed folder still on it,
// the card still mounted, and the app folder gone. Anything else keeps both folders.
const removeScript = `dir=$1 card=$2 keys=$3 sealed=$4 mounts=$5 tries=$6 gap=$7
i=0
while [ "$i" -lt "$tries" ]; do
	if [ ! -e "$dir" ]; then
		ls -a "$card" >/dev/null 2>&1 && [ -d "$sealed" ] && grep -q " $card " "$mounts" &&
			[ ! -e "$dir" ] && rm -rf "$keys" "$sealed"
		exit 0
	fi
	sleep "$gap"
	i=$((i + 1))
done
`

// watchRemove is removeScript for the app's card folder dir (its card the folder above), the key's
// folder keys and the sealed logins' folder sealed (on the same card), the mounts read from mounts;
// nil when a path is too short to trust with rm -rf, or sealed isn't a folder of dir's card.
func watchRemove(dir, keys, sealed, mounts string, tries int, gap string) *exec.Cmd {
	deep := func(p string, n int) bool {
		return filepath.IsAbs(p) && filepath.Clean(p) == p && len(strings.Split(strings.Trim(p, "/"), "/")) >= n
	}
	if !deep(keys, 3) || !deep(dir, 2) || !deep(sealed, 2) || filepath.Dir(sealed) != filepath.Dir(dir) ||
		sealed == dir {
		return nil
	}
	return exec.Command("/bin/sh", "-c", removeScript, "sh", dir, filepath.Dir(dir), keys, sealed, mounts,
		strconv.Itoa(tries), gap)
}

// startRemoveWatch starts the watch in a session of its own, so the launcher's KILL, 2 s after its
// TERM, leaves it running: a minute, every second.
func startRemoveWatch(dir, keys, sealed, mounts string, logf func(string, ...any)) {
	cmd := watchRemove(dir, keys, sealed, mounts, 60, "1")
	if cmd == nil {
		return
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		logf("remove watch: %v", err)
		return
	}
	cmd.Process.Release()
}
