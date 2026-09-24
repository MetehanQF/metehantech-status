"""Ortam bagimli ag adresleri icin tek config katmani.

Gercek degerler bu repoda DEGILDIR. systemd birimi bunlari su dosyadan yukler:

    /etc/metehantech-status/network.env      (root:root, 0644)

Sablon: network.env.example  (yalnizca RFC dokumantasyon adresleri icerir)

Tasarim karari — kaynak kodda gercek adres fallback'i BILEREK yoktur.
Bir deger eksikse modul sessizce yanlis bir adrese baglanmaya calismaz;
NetworkConfigError firlatir. Boylece yanlis yapilandirma, yanlis hedefe
istek atmak yerine acik bir hatayla ortaya cikar.

Testler production ortamina bagimli degildir: tests/conftest.py kendi
dokumantasyon araligindaki degerlerini enjekte eder.
"""

import os

import envfile

CONFIG_PATH = "/etc/metehantech-status/network.env"
EXAMPLE_PATH = "network.env.example"

#: Servisin calismasi icin gereken anahtarlar.
REQUIRED = (
    "PI5_LAN_IP",
    "PCOLD_LAN_IP",
    "CAMERA_LAN_IP",
    "PI5_TAILSCALE_IP",
    "PCOLD_TAILSCALE_IP",
)


class NetworkConfigError(RuntimeError):
    """Gerekli bir ag degeri tanimli degil."""


_FILE_VALUES = envfile.load("network.env")


def get(name):
    """Once ortam, sonra yapilandirma dosyasi. Bulunamazsa anlamli hata."""
    value = (os.environ.get(name) or _FILE_VALUES.get(name) or "").strip()
    if not value:
        raise NetworkConfigError(
            "{name} tanimli degil. {cfg} dosyasini {ex} sablonundan olusturun; "
            "systemd birimi onu EnvironmentFile ile yukler. Kaynak kodda gercek "
            "adres fallback'i bilerek birakilmamistir.".format(
                name=name, cfg=CONFIG_PATH, ex=EXAMPLE_PATH
            )
        )
    return value


def endpoint(name, port):
    """`<adres>:<port>` biciminde birlesik uc nokta."""
    return "{0}:{1}".format(get(name), port)


def missing():
    """Eksik zorunlu anahtarlarin listesi. Health check ve kurulum dogrulamasi icin."""
    return [k for k in REQUIRED
            if not (os.environ.get(k) or _FILE_VALUES.get(k) or "").strip()]


def verify():
    """Tum zorunlu anahtarlar tanimliysa True; degilse tek seferde hepsini bildir."""
    gaps = missing()
    if gaps:
        raise NetworkConfigError(
            "Eksik ag yapilandirmasi: {0}. Kaynak: {1}".format(", ".join(gaps), CONFIG_PATH)
        )
    return True
