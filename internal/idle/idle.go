// Package idle decides when the Vault may close: no app that uses it is
// running, and nobody has asked for its page.
package idle

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var idRe = regexp.MustCompile(`^[a-z0-9-]{1,15}$`)

// procRoot is where process directories live; tests point it elsewhere.
var procRoot = "/proc"

const (
	seenAfter = 30 * time.Second
	pageAfter = 60 * time.Second
	maxNeeds  = 4
)

// needsVault applies Q2 Pod's rules to one q2app file's text.
func needsVault(text string) bool {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSuffix(line, "\r")
		val, ok := strings.CutPrefix(line, "needs=")
		if !ok {
			continue
		}
		n := 0
		for _, item := range strings.Split(val, ",") {
			item = strings.Trim(item, " \r")
			if !idRe.MatchString(item) {
				continue
			}
			if item == "vault" {
				return true
			}
			if n++; n == maxNeeds {
				break
			}
		}
		return false
	}
	return false
}

// Users lists the apps that use the Vault: those whose .<id>/q2app says
// needs=vault, plus those with a <id>.sealed file. Never includes "vault".
func Users(card, sealedDir string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(id string) {
		if id != "vault" && idRe.MatchString(id) && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	if entries, err := os.ReadDir(card); err == nil {
		for _, e := range entries {
			id, ok := strings.CutPrefix(e.Name(), ".")
			if !ok || !idRe.MatchString(id) {
				continue
			}
			b, err := os.ReadFile(filepath.Join(card, e.Name(), "q2app"))
			if err != nil {
				continue
			}
			if needsVault(string(b)) {
				add(id)
			}
		}
	}
	if entries, err := os.ReadDir(sealedDir); err == nil {
		for _, e := range entries {
			if id, ok := strings.CutSuffix(e.Name(), ".sealed"); ok {
				add(id)
			}
		}
	}
	return out
}

// Running reports whether /tmp/q2-<id> holds the pid of a live process.
func Running(tmp, id string) bool {
	b, err := os.ReadFile(filepath.Join(tmp, "q2-"+id))
	if err != nil {
		return false
	}
	pid, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 32)
	if err != nil || pid <= 1 {
		return false
	}
	_, err = os.Stat(filepath.Join(procRoot, strconv.FormatUint(pid, 10)))
	return err == nil
}

// Tracker remembers when an app last used the Vault and when its page was
// last asked for. The zero value works and counts as just seen on first use.
// Safe for concurrent use.
type Tracker struct {
	Now func() time.Time

	mu         sync.Mutex
	started    bool
	seen, page time.Time
}

func (t *Tracker) now() time.Time {
	if t.Now != nil {
		return t.Now()
	}
	return time.Now()
}

// start must be called with mu held.
func (t *Tracker) start() time.Time {
	n := t.now()
	if !t.started {
		t.started, t.seen, t.page = true, n, n
	}
	return n
}

// Seen records that an app used the Vault or one is running.
func (t *Tracker) Seen() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.seen = t.start()
}

// Page records that the Vault's page was asked for.
func (t *Tracker) Page() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.page = t.start()
}

// Idle is true when Seen was 30 s or more ago and Page 60 s or more ago.
func (t *Tracker) Idle() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := t.start()
	return n.Sub(t.seen) >= seenAfter && n.Sub(t.page) >= pageAfter
}
