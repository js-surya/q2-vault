// Command q2-vault keeps other card apps' logins sealed on a Shanling Q2 running Q2 Pod, as a card app:
// each app asks for its own login over /tmp/q2-vault.sock (Q2VAULT/1), and the Vault's page lists the
// saved logins in Library → Apps. See docs/design.md.
package main

import (
	"context"
	crand "crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"q2-vault/internal/idle"
	"q2-vault/internal/missing"
	"q2-vault/internal/pages"
	"q2-vault/internal/proto"
	"q2-vault/internal/q2spot"
	"q2-vault/internal/store"
)

const version = "q2-v0.1"

func main() { os.Exit(cli(os.Args[1:], os.Stdout, os.Stderr)) }

// config is everything run needs; cli fills it from the flags, tests with temporary paths.
type config struct {
	Dir    string // the app's card folder, /mnt/mmc/.vault
	Card   string // the card, /mnt/mmc
	Sealed string // the sealed logins, /mnt/mmc/.q2vault
	Keys   string // the key and state.json in internal storage, /mnt/data/apps/vault
	Socket string // Q2VAULT/1, /tmp/q2-vault.sock
	Browse string // the page's Q2SPOT/1, /tmp/q2-vault.browse.sock
	Tmp    string // where card apps' pid files are, /tmp
	Mounts string // /proc/mounts
	Proc   string // /proc, for the caller check

	Now    func() time.Time
	Tick   time.Duration // how often running apps are checked: 5 s
	Rand   io.Reader     // for a new master key: /dev/hwrng, else the system's
	Logf   func(string, ...any)
	Serve  func(ctx context.Context, socket string, b proto.Backend, procRoot string, onUse func(string)) error
	OnStop func() // at TERM or INT (not an idle close): the removal watch

	running func(tmp, id string) bool // idle.Running; a hook for tests
}

// usersEvery is how often the list of apps that use the Vault is read again (card reads).
const usersEvery = 60 * time.Second

// wipe zeroes a key in memory; a variable so a test can see it done.
var wipe = func(k *[32]byte) { clear(k[:]) }

// cli is main without the process: the exit code. 0 is a stop (TERM, INT, idle), which ends the
// launcher's loop; anything else is a failure it restarts.
func cli(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("q2-vault", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var cfg config
	fs.StringVar(&cfg.Dir, "dir", "/mnt/mmc/.vault", "the app's card folder")
	fs.StringVar(&cfg.Card, "card", "/mnt/mmc", "the card's mount point")
	fs.StringVar(&cfg.Sealed, "sealed", "/mnt/mmc/.q2vault", "the folder of sealed logins")
	fs.StringVar(&cfg.Keys, "keys", "/mnt/data/apps/vault", "the master key's folder in internal storage")
	fs.StringVar(&cfg.Socket, "socket", "/tmp/q2-vault.sock", "the socket apps ask (Q2VAULT/1)")
	fs.StringVar(&cfg.Browse, "browse", "/tmp/q2-vault.browse.sock", "the page's socket (Q2SPOT/1)")
	fs.StringVar(&cfg.Tmp, "tmp", "/tmp", "where card apps' pid files are")
	fs.StringVar(&cfg.Mounts, "mounts", "/proc/mounts", "the mount table")
	fs.StringVar(&cfg.Proc, "proc", "/proc", "the process table")
	showVersion := fs.Bool("version", false, "print the version and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintln(stdout, version)
		return 0
	}
	var logMu sync.Mutex
	cfg.Logf = func(format string, a ...any) {
		logMu.Lock()
		defer logMu.Unlock()
		fmt.Fprintf(stderr, "%s %s\n", time.Now().Format("2006-01-02 15:04:05"), fmt.Sprintf(format, a...))
	}
	cfg.OnStop = func() { startRemoveWatch(cfg.Dir, cfg.Keys, cfg.Sealed, cfg.Mounts, cfg.Logf) }
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	cfg.Logf("%s starting", version)
	if err := run(ctx, cfg); err != nil {
		cfg.Logf("%v", err)
		return 1
	}
	cfg.Logf("stopped")
	return 0
}

// run serves until ctx ends (TERM, INT) or no app has used the Vault for a while, then stops serving,
// wipes the key from memory and returns. Never logs a secret or a key.
func run(ctx context.Context, cfg config) error {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Tick <= 0 {
		cfg.Tick = 5 * time.Second
	}
	if cfg.Rand == nil {
		cfg.Rand = keyRand("/dev/hwrng")
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	if cfg.Serve == nil {
		cfg.Serve = proto.Serve
	}
	if cfg.running == nil {
		cfg.running = idle.Running
	}
	logf := cfg.Logf

	key, err := store.LoadOrCreateKey(cfg.Keys, cfg.Rand)
	if err != nil {
		return fmt.Errorf("master key: %w", err)
	}
	st := &store.Store{Card: cfg.Card, Dir: cfg.Sealed, Mounts: cfg.Mounts, Master: key, Rand: crand.Reader, Now: cfg.Now}
	clear(key[:])

	if err := st.Clean(); err != nil {
		logf("clean: %v", err)
	}
	var missMu sync.Mutex
	missingNow := sweep(st, cfg)

	tracker := &idle.Tracker{Now: cfg.Now}
	tracker.Seen()

	// The page: its handlers are let finish before the key is wiped, and refused after.
	var pageMu sync.RWMutex
	closing := false
	var eraseMu sync.Mutex
	nm := &names{card: cfg.Card, read: readNames}
	inner := pages.Handler(pages.Deps{
		List:  st.List,
		Names: nm.Get,
		Missing: func() map[string]time.Time {
			missMu.Lock()
			defer missMu.Unlock()
			out := make(map[string]time.Time, len(missingNow))
			for id, t := range missingNow {
				out[id] = t
			}
			return out
		},
		Remove: func(id string) error {
			if err := st.Delete(id); err != nil {
				return err
			}
			logf("removed the login of %s", id)
			return nil
		},
		EraseAll: func() error {
			eraseMu.Lock()
			defer eraseMu.Unlock()
			err := eraseAll(st, cfg.Keys, cfg.Rand)
			if err == nil {
				logf("erased all logins; new key")
			}
			return err
		},
		Now:     cfg.Now,
		Version: version,
		OnPage:  func() { tracker.Page(); nm.Stale() },
	})
	page := func(op string, args []string) q2spot.Reply {
		pageMu.RLock()
		defer pageMu.RUnlock()
		if closing {
			return q2spot.Reply{Status: "error", Message: "The Vault is closing"}
		}
		return inner(op, args)
	}

	sctx, scancel := context.WithCancel(context.Background())
	defer scancel()
	vaultDone := make(chan error, 1)
	go func() { vaultDone <- cfg.Serve(sctx, cfg.Socket, st, cfg.Proc, func(string) { tracker.Seen() }) }()
	pageDone := make(chan struct{})
	go func() {
		defer close(pageDone)
		if err := q2spot.Serve(sctx, cfg.Browse, page); err != nil {
			logf("page socket: %v", err)
		}
	}()

	users := idle.Users(cfg.Card, cfg.Sealed)
	usersAt := cfg.Now()
	tick := time.NewTicker(cfg.Tick)
	defer tick.Stop()
	var serveErr error
	served := false
loop:
	for {
		select {
		case <-ctx.Done():
			logf("stopping")
			if cfg.OnStop != nil {
				cfg.OnStop()
			}
			break loop
		case serveErr = <-vaultDone:
			served = true
			if serveErr == nil {
				serveErr = errors.New("vault socket: stopped serving")
			}
			serveErr = fmt.Errorf("vault socket: %w", serveErr)
			break loop
		case <-tick.C:
			if now := cfg.Now(); now.Sub(usersAt) >= usersEvery || now.Before(usersAt) {
				users, usersAt = idle.Users(cfg.Card, cfg.Sealed), now
			}
			for _, id := range users {
				if cfg.running(cfg.Tmp, id) {
					tracker.Seen()
					break
				}
			}
			if tracker.Idle() {
				logf("no app uses the Vault: closing")
				break loop
			}
		}
	}

	// Stop serving; requests in progress (a write among them) finish first.
	scancel()
	if !served {
		if err := <-vaultDone; err != nil {
			logf("vault socket: %v", err)
		}
	}
	<-pageDone
	pageMu.Lock()
	closing = true
	pageMu.Unlock()
	eraseMu.Lock()
	wipe(&st.Master)
	eraseMu.Unlock()
	return serveErr
}

// sweep deletes the logins of apps missing 7 days, and returns the apps missing now. Only with the
// card's list in hand: with the card away nothing is swept and the state is kept as it was.
func sweep(st *store.Store, cfg config) map[string]time.Time {
	path := filepath.Join(cfg.Keys, "state.json")
	s, err := missing.Load(path) // an unreadable state is an empty one: logins kept longer, never less
	if err != nil {
		cfg.Logf("state: %v; starting afresh", err)
	}
	entries, err := st.List()
	if err != nil {
		cfg.Logf("saved logins: %v; no sweep", err)
		return s.Missing
	}
	ids := make([]string, len(entries))
	for i, e := range entries {
		ids[i] = e.ID
	}
	installed := func(id string) bool {
		_, err := os.Stat(filepath.Join(cfg.Card, "."+id, "q2-"+id))
		return err == nil
	}
	for _, id := range missing.Sweep(&s, ids, installed, cfg.Now()) {
		if err := st.Delete(id); err != nil {
			cfg.Logf("delete the login of %s (missing 7 days): %v", id, err)
			continue
		}
		cfg.Logf("deleted the login of %s: missing 7 days", id)
	}
	if err := s.Save(path); err != nil {
		cfg.Logf("state: %v", err)
	}
	return s.Missing
}

// eraseAll deletes every sealed login and puts a new master key in place, in memory and in keys/key.
// The card's files go first: with the card away nothing changes.
func eraseAll(st *store.Store, keys string, rand io.Reader) error {
	var k [32]byte
	defer clear(k[:])
	if _, err := io.ReadFull(rand, k[:]); err != nil {
		return err
	}
	err := st.EraseAll(k)
	if st.Master != k { // not adopted (the card away): the old key stays, in memory and on file
		return err
	}
	if werr := writeKey(filepath.Join(keys, "key"), k); werr != nil {
		return errors.Join(err, fmt.Errorf("new key: %w", werr))
	}
	return err
}

// writeKey writes a key file whole: tmp, fsync, rename, fsync the folder.
func writeKey(path string, k [32]byte) error {
	defer clear(k[:])
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(k[:])
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
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// keyRand reads from the hardware generator at hw, else (no such device, or it fails) the system's.
func keyRand(hw string) io.Reader { return hwFirst(hw) }

type hwFirst string

func (h hwFirst) Read(p []byte) (int, error) {
	if f, err := os.Open(string(h)); err == nil {
		n, err := io.ReadFull(f, p)
		f.Close()
		if err == nil {
			return n, nil
		}
	}
	return crand.Read(p)
}

// names is the page's id → name map, from each app's q2app name=, read once per page request (Stale
// at the request, the read at the first Get) rather than once per row.
type names struct {
	card string
	read func(card string) map[string]string

	mu    sync.Mutex
	stale bool
	m     map[string]string
}

func (n *names) Stale() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.stale = true
}

func (n *names) Get() map[string]string {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.stale || n.m == nil {
		n.m, n.stale = n.read(n.card), false
	}
	return n.m
}

// readNames reads name= from the q2app of each app on the card.
func readNames(card string) map[string]string {
	out := map[string]string{}
	des, err := os.ReadDir(card)
	if err != nil {
		return out
	}
	for _, de := range des {
		id, ok := strings.CutPrefix(de.Name(), ".")
		if !ok || id == "" || !de.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(card, de.Name(), "q2app"))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(strings.TrimSuffix(line, "\r"), "name="); ok {
				if v = strings.TrimSpace(v); v != "" {
					out[id] = v
				}
				break
			}
		}
	}
	return out
}
