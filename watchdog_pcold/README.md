# MetehanTechPcOld external watchdog

This is an independent, Python-standard-library-only service for the old laptop. It does not change the existing metrics API or Telegram scripts. It checks the Pi at `<PI5_LAN_IP>` every 60 seconds. Three consecutive failed ICMP/TCP checks open one persistent incident; the first successful check resolves it. SQLite lives at `/var/lib/metehantech-watchdog/events.db` via systemd `StateDirectory`.

The read-only endpoint binds only to `<PCOLD_LAN_IP>:8766` and accepts requests from the Pi address or loopback. The Pi dashboard imports `GET /incidents` every 60 seconds, using `external_event_id` to avoid duplicates.

## ⚠ Deploy on kosulu — once ag yapilandirmasi

`watchdog.py` artik adresleri kaynak kodunda TASIMAZ. `/etc/metehantech-watchdog/network.env`
olusturulmadan **yeni watchdog surumu PcOld'a deploy edilmemelidir**: dosya yoksa servis
yanlis bir host'u izlemek yerine `NetworkConfigError` ile durur.

Sablon: bu dizindeki `network.env.example` (yalnizca RFC 5737 sentetik adresler icerir).

Deploy sirasi degistirilemez:

```bash
# 1. ONCE yapilandirma (gercek degerleri elle girin)
sudo install -d -m 0755 /etc/metehantech-watchdog
sudo install -m 0600 network.env.example /etc/metehantech-watchdog/network.env
sudo nano /etc/metehantech-watchdog/network.env      # PI5_LAN_IP / PCOLD_LAN_IP
sudo grep -c '^[A-Z]' /etc/metehantech-watchdog/network.env   # 2 donmeli

# 2. SONRA kod ve birim
sudo install -d -m 755 /opt/metehantech-watchdog
sudo install -m 644 watchdog.py /opt/metehantech-watchdog/watchdog.py
sudo install -m 644 metehantech-watchdog.service /etc/systemd/system/metehantech-watchdog.service
sudo systemd-analyze verify /etc/systemd/system/metehantech-watchdog.service
sudo systemctl daemon-reload
sudo systemctl enable --now metehantech-watchdog

# 3. Dogrulama
systemctl is-active metehantech-watchdog
journalctl -u metehantech-watchdog -n 20 --no-pager   # NetworkConfigError OLMAMALI
curl http://<PCOLD_LAN_IP>:8766/incidents
```

Sirayi bozup once kodu kurarsaniz servis baslamaz. Geri donus: onceki `watchdog.py`
surumunu geri koyup `systemctl restart metehantech-watchdog`.

If a firewall blocks port 8766, allow only `<PI5_LAN_IP>` to reach TCP/8766 using the laptop's existing firewall manager. No public Internet rule is needed. The old laptop must keep its address `<PCOLD_LAN_IP>` and be powered on during a Pi outage; otherwise it cannot observe that outage.
