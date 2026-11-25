#!/bin/sh
# q2-vault for the Shanling Q2: static Go for 32-bit little-endian MIPS with soft float, staged with its
# card files in OUT/.vault and zipped as a release ships it, OUT/q2-vault-vX.Y-SHA.zip, to unzip at the
# card's root (or for System settings -> App Store to install). Adapted from q2-tailscale's (same author,
# MIT), itself from q2-subsonic's (MIT).
#   contrib/shanlingq2/build.sh [OUT]
# Needs Go (the version go.mod names) and python3.
set -eu
APP=vault
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
OUT=${1:-$ROOT/target/shanlingq2}
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
VERSION=$(sed -n 's/^const version = "q2-\(v[0-9.]*\)"$/\1/p' "$ROOT/cmd/q2-$APP/main.go")
[ -n "$VERSION" ] || { echo "build.sh: no version constant in cmd/q2-$APP/main.go" >&2; exit 1; }
SHA=$(git -C "$ROOT" rev-parse --short=7 HEAD 2>/dev/null || echo local)

R="$OUT/.$APP"
rm -rf "$R"
mkdir -p "$R"
cd "$ROOT"
CGO_ENABLED=0 GOOS=linux GOARCH=mipsle GOMIPS=softfloat \
    go build -trimpath -ldflags='-s -w -buildid=' -o "$R/q2-$APP" "./cmd/q2-$APP"
chmod 755 "$R/q2-$APP"
sh "$HERE/licenses.sh" "$R/LICENSES.txt" # the licences of what's in the binary, shipped beside it
for f in launcher.sh q2app icon.png icon-40.png; do
    case $f in launcher.sh) cp "$HERE/$f" "$R/run" && chmod 755 "$R/run" ;; *) cp "$HERE/$f" "$R/" && chmod 644 "$R/$f" ;; esac
done
rm -f "$OUT"/q2-$APP-*.zip
python3 -I "$HERE/package.py" "$R" "$OUT/q2-$APP-$VERSION-$SHA.zip"
