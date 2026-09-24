# MetehanTech Control Center setup

The public dashboard remains available at `/`. Admin routes are under `/admin` and management APIs under `/api/admin/`.

## 1. Create admin secrets

Generate values locally (do not paste them into chat or commit them):

```bash
mkdir -p /etc/metehantech-status
<PROJECT_ROOT>/.venv/bin/python -c 'from werkzeug.security import generate_password_hash; import getpass; print("ADMIN_PASSWORD_HASH=" + generate_password_hash(getpass.getpass("Admin password: ")))' | sudo tee /etc/metehantech-status/admin.env >/dev/null
printf 'ADMIN_SESSION_SECRET=%s\n' "$(openssl rand -hex 32)" | sudo tee -a /etc/metehantech-status/admin.env >/dev/null
printf 'ADMIN_DOCKER_CONTAINERS=\nADMIN_COOKIE_SECURE=1\n' | sudo tee -a /etc/metehantech-status/admin.env >/dev/null
sudo chmod 600 /etc/metehantech-status/admin.env
sudo chown root:root /etc/metehantech-status/admin.env
```

Container controls are disabled by default. If needed, set `ADMIN_DOCKER_CONTAINERS` to an operator-maintained comma-separated list of exact container names. Request values are always checked against that list.

## 2. Grant only the required restart permissions

`journalctl` is readable because `metehanqf` belongs to the `adm` group. Docker commands use the existing `docker` group. Service restarts need only these exact sudo rules; verify paths with `command -v systemctl` first:

```sudoers
metehanqf ALL=(root) NOPASSWD: /usr/bin/systemctl restart --no-block metehantech-status.service
metehanqf ALL=(root) NOPASSWD: /usr/bin/systemctl restart --no-block metehantech-home.service
metehanqf ALL=(root) NOPASSWD: /usr/bin/systemctl restart --no-block clan-web.service
```

Install them with `sudo visudo -f /etc/sudoers.d/metehantech-status-admin` and mode `0440`. Do not grant a wildcard `systemctl` or shell rule.

## 3. Install and restart the unit

Review the unit diff, then run:

```bash
sudo install -m 644 metehantech-status.service /etc/systemd/system/metehantech-status.service
sudo systemctl daemon-reload
sudo systemctl restart metehantech-status.service
```

Restart requests use `systemctl --no-block`. When the status service restarts itself, the API returns `202` first where scheduling permits, but the browser connection can still briefly drop. The session secret stored in the environment keeps the login cookie valid across that restart.
