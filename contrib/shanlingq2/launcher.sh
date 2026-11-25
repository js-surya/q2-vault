#!/bin/sh
# Installed as /mnt/mmc/.vault/run. Q2 Pod runs it to start the Vault: from its row, and with q2app's
# wifi=1 when Wi-Fi connects (it stops it again once Wi-Fi has been gone 10 s). It must return at once:
# the loop runs in the background, its pid in /tmp/q2-vault, and a TERM to that pid stops it.
# Adapted from q2-tailscale's launcher (same author, MIT), itself from q2-subsonic's (MIT). The app runs
# from the card. Q2 Pod stops it before USB storage takes the card.
# The loop restarts the app after a failure, waiting 5 s and doubling, at most a minute; an exit of 0 (TERM,
# or the Vault closing itself when no app uses it) ends it. A failed run's stderr and exit code are kept
# in /tmp/q2-vault.crash, which the next start appends to .vault/log.txt (its last 256 KiB kept).
T=${Q2VAULT_TMP:-/tmp}
pid=$T/q2-vault
crash=$T/q2-vault.crash
err=$T/q2-vault.err
# This runs as root, and any app can leave a link at any of these paths in /tmp: no link is ever
# followed. Each file is removed, then made anew with noclobber (set -C: a redirection onto anything
# already there, a link included, fails), and one is read only if it is a file of our own, not a link
# (an app can't swap a root file in /tmp, which is sticky).
set -C
ours() { [ ! -L "$1" ] && [ -f "$1" ] && [ -O "$1" ]; }
# Already running: say it's wanted, so a Vault about to close (no app for 30 s) stays for this start.
ours "$pid" && kill -0 "$(cat "$pid")" 2>/dev/null && {
    rm -f "$T/q2-vault.want" && : >"$T/q2-vault.want"
    exit 0
} 2>/dev/null
dir=$(cd "$(dirname "$0")" && pwd)
if ours "$crash" && [ -s "$crash" ]; then
    cat "$crash" >> "$dir/log.txt"
    if [ "$(wc -c < "$dir/log.txt")" -gt 262144 ]; then
        rm -f "$dir/log.txt.tmp"
        tail -c 262144 "$dir/log.txt" > "$dir/log.txt.tmp" && mv "$dir/log.txt.tmp" "$dir/log.txt"
    fi
fi
rm -f "$crash"
(
    child=
    # A TERM keeps a crash for the next start. An app that hasn't ended 2 s after its TERM is killed, so
    # the loop is gone within the 3 s Q2 Pod waits (addon.c's AWAY_MS); the Vault finishes a write in
    # progress and wipes its key on the TERM.
    trap '[ -n "$child" ] && kill -TERM $child 2>/dev/null && { (sleep 2; kill -KILL $child) 2>/dev/null & w=$!; wait $child; kill $w 2>/dev/null; }; rm -f "$pid" "$err" "$T/q2-vault.want"; exit 0' TERM INT
    delay=5
    while :; do
        rm -f "$err"
        "$dir/q2-vault" -dir "$dir" 2>"$err" &
        child=$!
        wait $child
        code=$? child=
        [ $code = 0 ] && break
        rm -f "$crash"
        { ours "$err" && cat "$err"; echo "exit $code"; } >"$crash"
        sleep $delay &
        wait $! # not sleep alone: a TERM interrupts a wait, but waits for a foreground sleep
        delay=$((delay * 2))
        [ $delay -gt 60 ] && delay=60
    done
    rm -f "$pid" "$err" "$T/q2-vault.want"
) </dev/null >/dev/null 2>&1 &
rm -f "$pid"
echo $! > "$pid"
