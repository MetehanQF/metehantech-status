#!/usr/bin/env bash
# metehantech-status systemd birimini kurar.
#
# Makineye ozel hicbir yol bu betikte SABIT DEGILDIR:
#   - proje kokü betigin kendi konumundan turetilir
#   - calistirma kullanicisi betigi calistirandir (veya RUN_USER ile verilir)
# Birim dosyasi bir SABLONDUR; __PROJECT_ROOT__ ve __RUN_USER__ burada ikame edilir.
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
run_user="${RUN_USER:-${SUDO_USER:-$(id -un)}}"
unit_name=metehantech-status.service
unit_source="$project_dir/$unit_name"
unit_target="/etc/systemd/system/$unit_name"
rendered="$(mktemp)"
trap 'rm -f "$rendered"' EXIT

[[ -f "$unit_source" ]] || { echo "Birim sablonu bulunamadi: $unit_source" >&2; exit 1; }
id "$run_user" >/dev/null 2>&1 || { echo "Kullanici yok: $run_user" >&2; exit 1; }
[[ -x "$project_dir/.venv/bin/gunicorn" ]] || {
  echo "Sanal ortam bulunamadi: $project_dir/.venv" >&2
  echo "  python3 -m venv .venv && .venv/bin/pip install -r requirements.txt" >&2
  exit 1
}

# Sablonu gercek degerlerle isle
sed -e "s|__PROJECT_ROOT__|$project_dir|g" \
    -e "s|__RUN_USER__|$run_user|g" \
    "$unit_source" > "$rendered"

if grep -q '__PROJECT_ROOT__\|__RUN_USER__' "$rendered"; then
    echo "Sablonda islenmemis yer tutucu kaldi" >&2
    exit 1
fi

echo "Kurulacak: $unit_target"
echo "  proje kokü : $project_dir"
echo "  kullanici  : $run_user"

sudo install -m 644 "$rendered" "$unit_target"
sudo systemd-analyze verify "$unit_target" || true
sudo systemctl daemon-reload

listener=$(ss -ltnp 'sport = :5200' || true)
if [[ $listener =~ pid=([0-9]+) ]]; then
    pid=${BASH_REMATCH[1]}
    process_dir=$(readlink -f "/proc/$pid/cwd")
    process_user=$(ps -o user= -p "$pid" | xargs)
    process_command=$(tr '\0' ' ' < "/proc/$pid/cmdline")
    if [[ $process_dir != "$project_dir" || $process_user != "$run_user" || $process_command != *"app.py"* ]]; then
        echo "Port 5200 is owned by an unexpected process; leaving it untouched." >&2
        exit 1
    fi
    echo "Stopping existing dashboard process $pid"
    kill "$pid"
    for _ in {1..20}; do
        if ! kill -0 "$pid" 2>/dev/null; then break; fi
        sleep 0.25
    done
fi

sudo systemctl enable --now "$unit_name"
systemctl is-active "$unit_name"
systemctl is-enabled "$unit_name"
