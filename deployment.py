"""Deployment-specific paths and accounts.

Iki tur deger vardir ve ayrimi bilinclidir:

1. Projenin KENDI dosyalari — hicbir yapilandirma gerektirmez, modulun konumundan
   turetilir (PROJECT_ROOT, DATA_DIR). Repoyu nereye klonlarsaniz dogru calisir.

2. DEPLOYMENT'a ozel degerler — SSH anahtari, uzak hesap adi, kardes proje
   dizinleri gibi seyler. Bunlar tahmin EDILMEZ; yapilandirmadan okunur:

       /etc/metehantech-status/deploy.env      (root:root 0600)

   systemd birimi onu EnvironmentFile ile yukler. Sablon: deploy.env.example

Kaynak kodda gercek makine yolu fallback'i BILEREK yoktur. Zorunlu bir deger
eksikse DeploymentConfigError firlatilir; opsiyonel bir deger eksikse ilgili
ozellik sessizce degil, ACIKCA devre disi kalir ve durum raporlanir.
"""

import os
from pathlib import Path

import envfile

#: Projenin kok dizini — kurulum yerinden bagimsiz.
PROJECT_ROOT = Path(__file__).resolve().parent

#: Uygulamanin kendi veritabanlari ve calisma durumu.
DATA_DIR = PROJECT_ROOT / "data"

CONFIG_PATH = "/etc/metehantech-status/deploy.env"
EXAMPLE_PATH = "deploy.env.example"


class DeploymentConfigError(RuntimeError):
    """Zorunlu bir deployment degeri tanimli degil."""


_FILE_VALUES = envfile.load("deploy.env")


def get(name):
    """Zorunlu deger; once ortam, sonra yapilandirma dosyasi."""
    value = (os.environ.get(name) or _FILE_VALUES.get(name) or "").strip()
    if not value:
        raise DeploymentConfigError(
            "{name} tanimli degil. {cfg} dosyasini {ex} sablonundan olusturun; "
            "systemd birimi onu EnvironmentFile ile yukler. Kaynak kodda gercek "
            "makine yolu fallback'i bilerek birakilmamistir.".format(
                name=name, cfg=CONFIG_PATH, ex=EXAMPLE_PATH
            )
        )
    return value


def optional(name, default=None):
    """Opsiyonel deger; once ortam, sonra dosya, sonra default."""
    value = (os.environ.get(name) or _FILE_VALUES.get(name) or "").strip()
    return value or default


def path(name):
    """Zorunlu yol."""
    return Path(get(name))


def optional_path(name):
    """Opsiyonel yol; tanimsizsa None. Cagiran ozelligi acikca devre disi birakmali."""
    value = optional(name)
    return Path(value) if value else None


def path_list(name):
    """Iki nokta ile ayrilmis opsiyonel yol listesi (PATH gibi). Tanimsizsa bos demet."""
    value = optional(name, "")
    return tuple(Path(p) for p in value.split(":") if p.strip())
