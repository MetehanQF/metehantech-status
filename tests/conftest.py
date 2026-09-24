"""Test ortami: ag yapilandirmasi production'dan bagimsiz enjekte edilir.

Testler /etc/metehantech-status/network.env dosyasina BAGIMLI DEGILDIR.
Buradaki degerler RFC dokumantasyon bloklarindan secilmistir:
    192.0.2.0/24   RFC 5737 (TEST-NET-1)
    100.64.0.0/10  RFC 6598 (CGNAT)

Neden modul seviyesinde ve fixture degil: uygulama modulleri (camera, incidents,
dns_center, backup_job ...) adresleri import aninda sabitler. conftest.py, test
modulleri import edilmeden once yuklendigi icin degerlerin burada atanmasi sart.

setdefault kullanilir: kabuk ortaminda bilincli bir deger varsa ona saygi duyulur,
boylece alternatif bir yapilandirmaya karsi da test kosulabilir.
"""

import os

TEST_NETWORK = {
    "PI5_LAN_IP": "192.0.2.20",
    "PCOLD_LAN_IP": "192.0.2.22",
    "CAMERA_LAN_IP": "192.0.2.110",
    "ROUTER_LAN_IP": "192.0.2.1",
    "PI5_TAILSCALE_IP": "100.64.0.10",
    "PCOLD_TAILSCALE_IP": "100.64.0.11",
    "PI5_WIFI_IFACE": "wlan-test",
    "ONBOARD_CONN": "test-onboard-wifi",
}

#: Deployment'a ozel degerler (deployment.py). Testler gercek makineye bagli
#: degildir; hepsi sentetiktir ve hicbiri var olan bir yolu gostermez.
TEST_DEPLOYMENT = {
    "BACKUP_REMOTE_USER": "backupuser",
    "BACKUP_SSH_KEY": "/nonexistent/test/backup_ed25519",
    "DNS_CREDENTIALS": "/nonexistent/test/dns-credentials.json",
}
TEST_NETWORK.update(TEST_DEPLOYMENT)

# Testler yapilandirma DOSYALARINDAN da etkilenmemeli. envfile.py ortamdan sonra
# /etc/... ve ~/.config/... altina bakar; burada arama dizinini var olmayan bir
# yola sabitleyerek gercek makinenin degerlerinin testlere sizmasini engelliyoruz.
os.environ.setdefault(
    "METEHANTECH_CONFIG_DIR", "/nonexistent/metehantech-test-config")

for _key, _value in TEST_NETWORK.items():
    os.environ.setdefault(_key, _value)
