#!/usr/bin/env bash
set -euo pipefail

# Makineye ozel degerler bu betikte SABIT DEGILDIR:
#   proje kokü  -> betigin konumundan turetilir
#   hedef host  -> TARGET_HOSTNAME ortam degiskeni (opsiyonel dogrulama)
#   hesap adi   -> RUN_USER / BACKUP_REMOTE_USER ortam degiskeni


PROJECT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUNDLE="$PROJECT/deploy/personal-cloud"
COMPOSE_DIR=/opt/metehantech-cloud
SECRETS=/etc/metehantech-cloud/secrets

[[ $(id -u) -eq 0 ]] || { echo "Run with sudo." >&2; exit 1; }
[[ -z "${TARGET_HOSTNAME:-}" || $(hostname -s) == "$TARGET_HOSTNAME" ]] \
  || { echo "Unexpected host: $(hostname -s)" >&2; exit 1; }
test -S /var/run/docker.sock
if ss -ltnH 'sport = :5300' | grep -q .; then
  echo "Port 5300 is already in use." >&2
  exit 1
fi
for name in metehantech-nextcloud-app metehantech-nextcloud-db metehantech-nextcloud-redis metehantech-nextcloud-cron; do
  ! docker container inspect "$name" >/dev/null 2>&1 || { echo "Container already exists: $name" >&2; exit 1; }
done

if ! docker compose version >/dev/null 2>&1; then
  apt-get install -y --no-install-recommends docker-compose-v2
fi

install -d -o root -g docker -m 0750 "$COMPOSE_DIR"
install -d -o root -g root -m 0700 "$SECRETS"
install -d -o root -g docker -m 0750 /srv/metehantech-cloud
install -d -o root -g docker -m 0750 /srv/metehantech-cloud/nextcloud
install -d -o root -g docker -m 0750 /srv/metehantech-cloud/nextcloud/html
install -d -o root -g docker -m 0750 /srv/metehantech-cloud/nextcloud/data
install -d -o root -g docker -m 0750 /srv/metehantech-cloud/postgres
install -d -o root -g docker -m 0750 /srv/metehantech-cloud/redis

install -o root -g docker -m 0640 "$BUNDLE/compose.yaml" "$COMPOSE_DIR/compose.yaml"
install -o root -g docker -m 0640 "$BUNDLE/.env" "$COMPOSE_DIR/.env"
install -o root -g docker -m 0644 "$BUNDLE/redis.conf" "$COMPOSE_DIR/redis.conf"
install -o root -g docker -m 0644 "$BUNDLE/apache-proxy.conf" "$COMPOSE_DIR/apache-proxy.conf"
install -o root -g docker -m 0644 "$BUNDLE/apache-vhost.conf" "$COMPOSE_DIR/apache-vhost.conf"

umask 077
if [[ ! -e "$SECRETS/postgres-password" ]]; then openssl rand -base64 48 | tr -d '\n' > "$SECRETS/postgres-password"; fi
if [[ ! -e "$SECRETS/redis-password" ]]; then openssl rand -base64 48 | tr -d '\n' > "$SECRETS/redis-password"; fi
if [[ ! -e "$SECRETS/nextcloud-admin-password" ]]; then openssl rand -base64 48 | tr -d '\n' > "$SECRETS/nextcloud-admin-password"; fi
if [[ ! -e "$SECRETS/nextcloud-admin-user" ]]; then printf 'mtc_admin_%s' "$(openssl rand -hex 4)" > "$SECRETS/nextcloud-admin-user"; fi
printf 'user default on >%s ~* &* +@all\n' "$(cat "$SECRETS/redis-password")" > "$SECRETS/redis.acl"
chmod 0444 "$SECRETS"/*

install -m 0644 "$BUNDLE/metehantech-backup-cloud.service" /etc/systemd/system/metehantech-backup-cloud.service
install -m 0440 "$BUNDLE/50-metehantech-backup-cloud" /etc/sudoers.d/50-metehantech-backup-cloud
/usr/sbin/visudo -cf /etc/sudoers.d/50-metehantech-backup-cloud
python3 - <<'PY'
from pathlib import Path
p=Path('/etc/metehantech-status/admin.env')
line='ADMIN_DOCKER_CONTAINERS=metehantech-nextcloud-app,metehantech-nextcloud-db,metehantech-nextcloud-redis,metehantech-nextcloud-cron'
rows=p.read_text().splitlines() if p.exists() else []
rows=[row for row in rows if not row.startswith('ADMIN_DOCKER_CONTAINERS=')]
p.write_text('\n'.join(rows+[line])+'\n')
p.chmod(0o600)
PY
systemctl daemon-reload
systemd-analyze verify /etc/systemd/system/metehantech-backup-cloud.service

cd "$COMPOSE_DIR"
docker compose config --quiet
docker compose pull
docker compose up -d db redis app

for _ in $(seq 1 180); do
  health=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' metehantech-nextcloud-app 2>/dev/null || true)
  [[ $health == healthy ]] && break
  [[ $health == unhealthy ]] && { docker logs --tail 80 metehantech-nextcloud-app >&2; exit 1; }
  sleep 5
done
[[ ${health:-} == healthy ]] || { echo "Nextcloud readiness timeout" >&2; exit 1; }

docker compose up -d cron
gateway=$(docker network inspect metehantech-cloud_frontend --format '{{(index .IPAM.Config 0).Gateway}}')
curl -fsS -H 'Host: cloud.metehantech.com' http://127.0.0.1:5300/status.php >/dev/null
docker logs --since 20s metehantech-nextcloud-app 2>&1 | grep -F "$gateway" >/dev/null || {
  echo "Observed proxy address did not match Docker frontend gateway." >&2
  exit 1
}

occ=(docker exec -u 33 metehantech-nextcloud-app php occ)
"${occ[@]}" config:system:set trusted_proxies 0 --value="$gateway"
"${occ[@]}" config:system:set overwritehost --value=cloud.metehantech.com
"${occ[@]}" config:system:set overwriteprotocol --value=https
"${occ[@]}" config:system:set overwrite.cli.url --value=https://cloud.metehantech.com
"${occ[@]}" config:system:set files.chunked_upload.max_size --type=integer --value=52428800
"${occ[@]}" background:cron
"${occ[@]}" app:enable twofactor_totp
"${occ[@]}" app:disable registration >/dev/null 2>&1 || true

install -o root -g docker -m 0644 /dev/null /srv/metehantech-cloud/.alerts-enabled

systemctl restart --no-block metehantech-status.service
for _ in $(seq 1 60); do
  curl -fsS --max-time 2 http://127.0.0.1:5200/api/status >/dev/null 2>&1 && break
  sleep 1
done
curl -fsS http://127.0.0.1:5200/api/status >/dev/null

printf 'Admin username: %s\n' "$(cat "$SECRETS/nextcloud-admin-user")"
echo "Personal Cloud local deployment completed. Cloudflare route was not changed."
