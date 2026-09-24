#!/usr/bin/env bash
set -euo pipefail

# Makineye ozel degerler bu betikte SABIT DEGILDIR:
#   proje kokü  -> betigin konumundan turetilir
#   hedef host  -> TARGET_HOSTNAME ortam degiskeni (opsiyonel dogrulama)
#   hesap adi   -> RUN_USER / BACKUP_REMOTE_USER ortam degiskeni


[[ -z "${TARGET_HOSTNAME:-}" \
   || "$(hostname -s | tr '[:upper:]' '[:lower:]')" == "$(echo "$TARGET_HOSTNAME" | tr '[:upper:]' '[:lower:]')" ]] \
  || { echo "Beklenmeyen host: $(hostname -s) (beklenen $TARGET_HOSTNAME)" >&2; exit 1; }
[[ ${EUID} -eq 0 ]] || { echo "Run with sudo on PcOld" >&2; exit 1; }
source_root=${1:-/tmp/metehantech-backup-center}
bundle="$source_root/deploy/backup-center"

backup_user="${BACKUP_REMOTE_USER:?BACKUP_REMOTE_USER tanimlanmali (ornek: backupuser)}"
id "$backup_user" >/dev/null
install -d -o "$backup_user" -g "$backup_user" -m 0750 /srv/metehantech-backups/from-pi
install -d -o "$backup_user" -g "$backup_user" -m 0700 /srv/metehantech-backups/from-pi/.staging
install -d -o root -g "$backup_user" -m 0750 /var/lib/metehantech-backup/export
install -d -o "$backup_user" -g "$backup_user" -m 0700 /var/lib/metehantech-backup/requests
install -d -o root -g "$backup_user" -m 0750 /var/lib/metehantech-backup/status
install -d -o root -g root -m 0755 /usr/local/libexec
install -m 0755 "$source_root/backup/pcold_export.py" /usr/local/libexec/metehantech-backup-pcold-export
install -m 0755 "$source_root/backup/pcold_receiver.py" /usr/local/libexec/metehantech-backup-receiver
install -m 0644 "$bundle/metehantech-backup-export.service" /etc/systemd/system/metehantech-backup-export.service
install -m 0440 "$bundle/50-metehantech-backup-pcold" /etc/sudoers.d/50-metehantech-backup-pcold
/usr/sbin/visudo -cf /etc/sudoers.d/50-metehantech-backup-pcold
systemctl daemon-reload

echo "PcOld Backup Center support installed. No job or timer was started."
