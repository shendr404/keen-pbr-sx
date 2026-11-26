#!/bin/sh
set -u

# stop_xray from the S80keen-pbr-sx init script: stops the process named in the
# pid file only when /proc/PID/comm is "xray", and always removes the pid file.
repo_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
init_script="$repo_root/packages/keenetic/keen-pbr-sx/files/opt/etc/init.d/S80keen-pbr-sx"
work=$(mktemp -d)
trap 'kill "$fake_pid" "$other_pid" 2>/dev/null; rm -rf "$work"' EXIT

awk '/^stop_xray\(\)/ { keep=1 } keep { print } keep && /^}/ { exit }' "$init_script" > "$work/fn.sh"
[ -s "$work/fn.sh" ] || { echo "stop_xray not found" >&2; exit 1; }
. "$work/fn.sh"
log() { :; }
log_warn() { :; }
XRAY_PIDFILE="$work/xray.pid"

cp "$(command -v sleep)" "$work/xray"
"$work/xray" 60 &
fake_pid=$!
cp "$(command -v sleep)" "$work/other"
"$work/other" 60 &
other_pid=$!

# 1. a real "xray" process is stopped and the pid file removed
echo "$fake_pid" > "$XRAY_PIDFILE"
stop_xray
wait "$fake_pid" 2>/dev/null
[ ! -e "$XRAY_PIDFILE" ] || { echo "pid file not removed" >&2; exit 1; }
[ ! -d "/proc/$fake_pid" ] || { echo "xray not stopped" >&2; exit 1; }

# 2. a pid that is not xray (recycled pid) is left alone
echo "$other_pid" > "$XRAY_PIDFILE"
stop_xray
[ -d "/proc/$other_pid" ] || { echo "non-xray process was killed" >&2; exit 1; }
[ ! -e "$XRAY_PIDFILE" ] || { echo "stale pid file not removed" >&2; exit 1; }

# 3. garbage and a missing file are harmless
echo "not-a-pid" > "$XRAY_PIDFILE"
stop_xray
[ ! -e "$XRAY_PIDFILE" ] || { echo "garbage pid file not removed" >&2; exit 1; }
stop_xray

echo "ok"
