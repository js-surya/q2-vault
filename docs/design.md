# Vault: a card app that keeps other card apps' logins sealed — Design

_2026-11-25 · for Q2 Pod, as a card app_

## Intent

Card apps keep their logins as plain files on the SD card, which is exFAT: no permissions, every file readable by
anyone who pulls the card, uses USB storage, or runs another card app. Checked from their source: Jellyfin (an
access token), Deezer (the `arl` cookie: the account itself), Plex (`.plex/auth.json`: account and server tokens),
Subsonic (credentials), Soulseek (account), Spotify (a reusable token). Q2 Pod's own secrets (Wi-Fi, TIDAL,
Bluetooth, `q2remote.key`) are already root-only in `/mnt/data`.

A firmware vault was judged too big by DiamondBond (many entry points, an App Store ABI change). He'd add one that
lives in a **card app**. The PIN lock is his, in the firmware, minimal; it is not part of this design.

**Vault** is that card app: one key inside the Q2, each app's login sealed on the card, handed only to the app it
belongs to.

## Goals

- A card read anywhere else shows only ciphertext for every app that uses the Vault.
- Only the Vault touches internal storage (`root=1`); apps that use it run without root, as today.
- No firmware code for the Vault itself. One optional, generic firmware key (`needs=`) makes it smooth.
- An app that uses the Vault works unchanged where no Vault is installed.
- Playback and streaming never wait on the Vault: no PIN, nothing to unlock.
- Light: nothing running when no app needs it; no work while idle.

## Non-goals

- Protection against a root shell or a dump of the internal flash: the X2000 exposes no hardware key.
- Isolating card apps from each other completely: they share uid 1000 (see Limits).
- The firmware's own logins (`.scrobble.ini`): they need firmware code; a separate issue.
- Encrypting music, settings or caches. A PIN lock.

## Anti-goals

- An app signed out by the Vault's own lifecycle (closing, Wi-Fi drops, USB storage, an update).
- A login lost by a power cut or a pulled card mid-write.
- Anything that makes a card app's start noticeably slower, or uses battery while idle.
- Claiming protection the Q2 can't give.

## Constraints (from Q2 Pod's main, checked)

- Card apps live in `.<id>/` (id: 1–15 of `a-z0-9-`) with `q2app`, `run` and `q2-<id>`; the launcher leaves its
  pid in `/tmp/q2-<id>` and removes it as it ends; a TERM stops it (`docs/internals.md`, card apps).
- `run` is started as uid 1000 unless `q2app` has `root=1` (`patch/app_user.c`).
- `wifi=1` apps start when Wi-Fi connects (at boot too, once the card is mounted) and stop 10 s after it drops; an
  app that ends by itself is not restarted until Wi-Fi comes back after 10 s down (`wifi_off`).
- USB storage stops every app (up to 3 s) and starts again those that were running.
- `row=library` puts an app's row in Library → Apps. Pages are served over Q2SPOT/1 on `/tmp/q2-<id>.browse.sock`.
- Binaries must be built and packaged by the app's own `build.sh` (32-bit MIPS, soft float, the nan2008 ELF flag).
- The App Store installs a release zip packing `.<id>/q2-<id>`; each release has its own version tag.

## Approaches considered

| Approach | Verdict |
|---|---|
| Vault and PIN lock in the firmware (first proposal) | Rejected by the maintainer: too much firmware |
| Firmware hands each app its key on fd 3 at launch | Rejected: firmware code, and every app needs crypto |
| **A `root=1` card app serving each app its own login over a Unix socket** | **Chosen**: no firmware code; apps need no crypto |
| One shared vault file | Rejected: two apps saving at once collide; damage loses every login |
| Start the Vault only with `wifi=1` | Kept only as a fallback: logins then need Wi-Fi |
| **Start it with the app that needs it (`needs=`)** | **Chosen**, pending DiamondBond: works offline too |
| The app starts the Vault itself | Impossible: started by a uid 1000 app, it wouldn't be root |

## Design

### Files

| Path | What | Who |
|---|---|---|
| `/mnt/data/apps/vault/key` | 32 random bytes, the master key | root 0600, folder 0700 |
| `/mnt/data/apps/vault/state.json` | apps seen missing, with the date first seen | root 0600 |
| `/mnt/mmc/.vault/` | the app: `q2app`, `run`, `q2-vault`, icons | the card |
| `/mnt/mmc/.q2vault/<id>.sealed` | one app's sealed login | the card |
| `/tmp/q2-vault.sock` | the socket apps ask | root, mode 0666 |
| `/tmp/q2-vault.browse.sock` | the Vault's own page | as any card app |

The sealed files are in `.q2vault/`, **not** in the app's own folder `.vault/`: an App Store update or remove works
on `.vault/`, and must never touch the logins. The firmware ignores `.q2vault/` (no `q2app` in it), and Q2 Pod's
Wi-Fi transfer refuses every dot-folder.

`q2app`: `name=Vault`, `root=1`, `row=library`, `wifi=1`.

### Keys and sealing

- **Master key:** made at first start from `/dev/hwrng` (else `/dev/urandom`), written whole (tmp, fsync, rename),
  read into memory at each start, wiped from memory on exit.
- **An app's key:** `BLAKE2b-256(key = master, message = "q2pod-vault/v1/" + id)`. Nothing per app is stored.
- **Sealed file:** `"Q2VT"` (4 bytes) · version `1` (1 byte) · nonce (24 random bytes) · XChaCha20-Poly1305
  ciphertext and tag of the app's secret, with `"q2pod-vault/v1/" + id` as associated data, so a file renamed to
  another app fails to open. Go's `golang.org/x/crypto` (`chacha20poly1305`, `blake2b`).
- **The secret is opaque:** whatever bytes the app puts (its old `auth.json`, a token); at most **16 KB**.
- **Writing:** `<id>.sealed.tmp`, fsync, rename over `<id>.sealed`, fsync the folder. A cut-off write leaves the
  old file.

### The socket: Q2VAULT/1

One request per connection, as Q2SPOT/1. The app writes its request and shuts its write side; the Vault answers
and closes. Text lines end in `\n`; a body follows the second line as raw bytes.

```
request:  Q2VAULT/1\n<op>\n[body]        op: get | put | delete
answer:   Q2VAULT/1\n<status>\n[body]    status: ok | none | refused | too-large | card-away | bad-request
```

| Op | Body | Answer |
|---|---|---|
| `get` | none | `ok` + the secret, or `none` when the app has none saved |
| `put` | the secret (1 byte to 16 KB) | `ok` once sealed and written; `too-large` over 16 KB |
| `delete` | none | `ok`, whether or not one existed |

- `refused`: the caller isn't a card app (below). `card-away`: the card isn't mounted (USB storage, removed), so
  `get` can't tell `none` from a login it can't read; the app keeps what it has in memory and asks again later.
  `bad-request`: anything malformed. A sealed file that won't open (wrong key, damaged) answers `none` and is set
  aside as `<id>.sealed.bad`, never deleted silently, so the app signs in again.
- Requests over 16 KB + 64 bytes are cut off with `too-large`. A connection idle 5 s is closed.

### Who is asking

1. The kernel's peer credentials on the socket give the caller's pid (it can't be faked).
2. `/proc/<pid>/exe` must be `/mnt/mmc/.<id>/q2-<id>`, with `<id>` a valid card app id and the same id twice. The
   id names the entry. Anything else, the Vault's own binary included, is `refused`.
3. A caller can only reach its own `<id>.sealed`: the request carries no app name.

### Lifecycle

- **Starting:** with `needs=vault` the firmware starts the Vault before an app that needs it. Without it,
  `wifi=1` starts it when Wi-Fi connects, and opening its row starts it as any card app.
- **An app that finds no socket:** if `.vault/q2-vault` exists, it retries for up to 5 s (the Vault may be
  starting); if not, or still no socket, it uses its own file as before.
- **Closing itself:** every 5 s the Vault checks the pid files `/tmp/q2-<id>` (alive: the pid exists) of the card
  apps whose `q2app` says `needs=vault`, a list it reads at start and again every 60 s (not every 5 s: card reads).
  Apps that have a sealed file count too, for firmware without `needs=`. When none has run for 30 s, and its own page hasn't been asked for
  in 60 s, it wipes the key, removes its socket and pid file, and exits. An app streaming in the background is
  still running, so the Vault stays. Apps keep their secret in memory, so closing signs nothing out.
- **USB storage, shutdown:** the firmware's TERM: the Vault finishes any write in progress, wipes the key, exits.
- **Updating the Vault:** an App Store update replaces the binary; the key and sealed files stay.
- **Removing the Vault:** if it's running, it notices its binary is gone (as the Tailscale app does, within a
  minute) and deletes `/mnt/data/apps/vault/` and `.q2vault/`. If it isn't running, the key stays (32 bytes, root
  only): reinstalling the Vault then opens the same sealed files, so nobody signs in again. Erase All Logins is the
  way to wipe on purpose.

### A removed app's login

The App Store deletes an app's folder, not `.q2vault/<id>.sealed`. At each start the Vault checks each sealed
file's `.<id>/q2-<id>`. A missing one is written to `state.json` with today's date, shown on the page as
"(not installed)", and deleted once it's still missing 7 days later. Not at once: an App Store update moves an
app's files briefly, a swapped card makes every app look missing, and a same-day reinstall should keep the login.
An app that's back is taken off the list.

### The page (Library → Apps → Vault)

```
Vault
  Running · 3 saved logins
  Plex              saved 25 Nov
  Jellyfin          saved 20 Nov
  Deezer (not installed)
  Erase All Logins
  About
```

- An app's row opens **Remove** (asks first): deletes its sealed file; it asks to sign in next time.
- **Erase All Logins** (asks first, press twice as the Tailscale app's Sign Out): deletes every sealed file and
  makes a new key. For selling or lending the Q2. Apps already running keep the login in memory until they stop;
  a `put` from one of them is sealed with the new key.
- Names come from each app's `q2app` `name=`, else its id. The page never shows a secret.

### For app makers

- **Client**: a Go package, `vault.Get() ([]byte, error)`, `vault.Put([]byte) error`, `vault.Delete()`,
  with `vault.ErrNoVault` when no Vault is installed, and the 5 s retry. Other languages: the protocol above.
- **`q2app`:** `needs=vault` (when the firmware has it).
- **Moving in:** at start, with a Vault and an old plain file: `put` its contents, `get` and compare, then delete
  the plain file. With no Vault, keep using the plain file.
- **Advice:** keep tokens, not passwords; Sign Out calls `delete`; call `prctl(PR_SET_DUMPABLE, 0)` at start so
  other uid 1000 apps can't read its memory.

### The firmware ask (DiamondBond's call)

`needs=a[,b]` in `q2app`: the App Store installs the needed apps with it (asking first), and the launcher starts
each needed app that isn't running before starting the app. Generic: nothing names the Vault. Older firmware
ignores it; the Vault still works through `wifi=1` and its row.

## Limits (for the README)

- The key is in internal storage, root only. A root shell or a flash dump reads it.
- An app that overwrites another app's binary on the card (`.plex/q2-plex`) would be handed that app's login at
  its next start. Later: the App Store records each binary's hash at install, and the Vault answers only a match.
- A process that connects and then runs another app's binary in its place reaches that binary's code, not its
  secret; noted as a limit, not a hole.
- Swapping cards: the other card's logins stay on that card; on this one, apps sign in again.
- Logins only.

## Testing

- **Unit (host):** seal and open round trip; wrong key; a changed byte; a renamed file; 16 KB and one byte over;
  power cut between the tmp and the rename; key derivation separates ids; the protocol's every status;
  the caller check (a fake `/proc` root: an app's binary, the Vault's own, a non-card path, an id mismatch);
  idle exit (no needing app for 30 s; a page asked for keeps it); a missing app kept 6 days, deleted on the 7th,
  taken off when back.
- **On the Q2**: a test app or Plex moves its `auth.json` in; the plain file is gone; it still signs in
  after a reboot, USB storage, the Vault closing, a Wi-Fi drop; another app asking gets `refused`; the card read
  on a computer shows only ciphertext; start time and RAM measured.

## Left to the builder

The Go module layout, the page's exact wording, logging (no secret or key ever logged), and the release workflow
(as the Tailscale app's). Repository: `q2-vault` beside the other projects, MIT like the Tailscale app.

## Calls made in this design (check while reading)

- Sealed logins in `.q2vault/`, apart from the app's folder `.vault/`.
- 16 KB cap per app; a 5 s retry for an app that finds no socket yet; idle exit after 30 s (60 s after the page).
- `q2app` reread every 60 s, not every 5 s.
- A removed Vault keeps its key when it wasn't running, so a reinstall keeps the logins.
- An unreadable sealed file answers `none` and is kept as `.bad`.
- Go with `x/crypto` (XChaCha20-Poly1305, BLAKE2b); MIT.
