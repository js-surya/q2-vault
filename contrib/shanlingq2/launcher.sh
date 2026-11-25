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
# Already running: say it's wanted, so a Vault about to close (no app for 30 s) stays for this start.
[ -f "$pid" ] && kill -0 "$(cat "$pid")" 2>/dev/null && { touch "$T/q2-vault.want"; exit 0; }
dir=$(cd "$(dirname "$0")" && pwd)
if [ -s "$T/q2-vault.crash" ]; then
    cat "$T/q2-vault.crash" >> "$dir/log.txt"
    rm -f "$T/q2-vault.crash"
    if [ "$(wc -c < "$dir/log.txt")" -gt 262144 ]; then
        tail -c 262144 "$dir/log.txt" > "$dir/log.txt.tmp" && mv "$dir/log.txt.tmp" "$dir/log.txt"
    fi
fi
(
    child=
    # A TERM keeps a crash for the next start. An app that hasn't ended 2 s after its TERM is killed, so
    # the loop is gone within the 3 s Q2 Pod waits (addon.c's AWAY_MS); the Vault finishes a write in
    # progress and wipes its key on the TERM.
    trap '[ -n "$child" ] && kill -TERM $child 2>/dev/null && { (sleep 2; kill -KILL $child) 2>/dev/null & w=$!; wait $child; kill $w 2>/dev/null; }; rm -f "$pid" "$T/q2-vault.err" "$T/q2-vault.want"; exit 0' TERM INT
    delay=5
    while :; do
        "$dir/q2-vault" -dir "$dir" 2>"$T/q2-vault.err" &
        child=$!
        wait $child
        code=$? child=
        [ $code = 0 ] && break
        { cat "$T/q2-vault.err"; echo "exit $code"; } >"$T/q2-vault.crash"
        sleep $delay &
        wait $! # not sleep alone: a TERM interrupts a wait, but waits for a foreground sleep
        delay=$((delay * 2))
        [ $delay -gt 60 ] && delay=60
    done
    rm -f "$pid" "$T/q2-vault.err" "$T/q2-vault.want"
) </dev/null >/dev/null 2>&1 &
echo $! > "$pid"
