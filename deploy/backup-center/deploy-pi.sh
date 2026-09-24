#!/usr/bin/env bash
set -euo pipefail

# Makineye ozel degerler bu betikte SABIT DEGILDIR:
#   proje kokü  -> betigin konumundan turetilir
#   hedef host  -> TARGET_HOSTNAME ortam degiskeni (opsiyonel dogrulama)
#   hesap adi   -> RUN_USER / BACKUP_REMOTE_USER ortam degiskeni


[[ -z "${TARGET_HOSTNAME:-}" || "$(hostname -s)" == "$TARGET_HOSTNAME" ]] \
  || { echo "Beklenmeyen host: $(hostname -s) (beklenen $TARGET_HOSTNAME)" >&2; exit 1; }
[[ ${EUID} -eq 0 ]] || { echo "Run with sudo on the Pi" >&2; exit 1; }
project="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
run_user="${RUN_USER:-${SUDO_USER:-$(id -un)}}"
bundle="$project/deploy/backup-center"

install -d -o "$run_user" -g "$run_user" -m 0750 /srv/metehantech-backups/from-pcold
install -d -o "$run_user" -g "$run_user" -m 0700 /srv/metehantech-backups/from-pcold/.staging
install -m 0644 "$bundle/metehantech-backup-pi.service" /etc/systemd/system/metehantech-backup-pi.service
install -m 0644 "$bundle/metehantech-backup-pcold.service" /etc/systemd/system/metehantech-backup-pcold.service
install -m 0440 "$bundle/50-metehantech-backup-pi" /etc/sudoers.d/50-metehantech-backup-pi
/usr/sbin/visudo -cf /etc/sudoers.d/50-metehantech-backup-pi
systemctl daemon-reload

echo "Pi Backup Center support installed. No job or timer was started."
