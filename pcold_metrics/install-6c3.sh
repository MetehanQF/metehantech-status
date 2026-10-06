#!/usr/bin/env bash
# PcOld metrics agent: interval CPU sampling (Phase 6C.3).
# Run ON PcOld as root from the staging user's home:  sudo bash ~/pcold-metrics-install-6c3.sh
# Installs the staged agent, verifies it, and rolls back automatically on any failure.
set -euo pipefail
# The staged file lives in the home of the user that invoked sudo (override with STAGE_DIR).
STAGE_DIR="${STAGE_DIR:-$(getent passwd "${SUDO_USER:-root}" | cut -d: -f6)}"
SRC="$STAGE_DIR/metehantech-metrics.py.new"
DST=/usr/local/bin/metehantech-metrics.py
BACKUP=/usr/local/bin/metehantech-metrics.py.pre-6c3
UNIT=metehantech-metrics.service
EXPECTED_SHA=165ee14af376c2deb9af2c17b51f0148b800e64ef53463b73e185c2dcb492434

rollback() {
  echo "!! verification failed — restoring $BACKUP" >&2
  install -m 755 -o root -g root "$BACKUP" "$DST"
  systemctl restart "$UNIT"
  sleep 2
  systemctl is-active --quiet "$UNIT" && echo "rollback complete: previous agent active" >&2
  exit 1
}

[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 2; }
[[ "$(sha256sum "$SRC" | cut -d' ' -f1)" == "$EXPECTED_SHA" ]] || { echo "staged file checksum mismatch; nothing changed" >&2; exit 2; }
python3 -c "import ast,sys; ast.parse(open(sys.argv[1]).read())" "$SRC"
[[ -e "$BACKUP" ]] || cp -p "$DST" "$BACKUP"
echo "backup: $BACKUP ($(sha256sum "$BACKUP" | cut -d' ' -f1))"

trap rollback ERR
install -m 755 -o root -g root "$SRC" "$DST"
systemctl restart "$UNIT"
sleep 2
systemctl is-active --quiet "$UNIT"
first=$(python3 -c "import json,urllib.request;d=json.load(urllib.request.urlopen('http://127.0.0.1:8765/status',timeout=3));print(d['cpu'])")
echo "warm-up cpu (null expected): $first"
echo "waiting 35 s for the first interval value…"
sleep 35
second=$(python3 -c "import json,math,urllib.request;d=json.load(urllib.request.urlopen('http://127.0.0.1:8765/status',timeout=3));v=d['cpu'];assert isinstance(v,(int,float)) and math.isfinite(v) and 0<=v<=100, v;print(v)")
trap - ERR
echo "interval cpu: $second %"
echo "OK — PcOld agent updated. Rollback: sudo install -m 755 $BACKUP $DST && sudo systemctl restart $UNIT"
