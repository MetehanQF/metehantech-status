"""Yapilandirma dosyasi okuyucusu (systemd EnvironmentFile semantigi).

NEDEN VAR: bu projenin parcalari uc farkli baglamda calisir —
  1. sistem servisi  (systemd, EnvironmentFile ile env dolu gelir)
  2. kullanici timer'lari (systemd --user; EnvironmentFile YOK)
  3. elle calistirma (kabuk)

Yalnizca os.environ'a bakmak (2) ve (3) icin yetersizdir: kullanici birimleri
ortami almaz ve /etc altindaki 0600 root dosyasini okuyamaz. Bu yuzden
degerler once ortamdan, bulunamazsa asagidaki sirayla bir dosyadan okunur:

    $METEHANTECH_CONFIG_DIR/<ad>
    /etc/metehantech-status/<ad>          (sistem genelinde, root tarafindan kurulur)
    ~/.config/metehantech-status/<ad>     (kullanici birimleri icin okunabilir)

Ayristirma kabuk DEGILDIR: 'KEY=iki kelime' gibi degerler bozulmadan okunur.
Cevreleyen tek/cift tirnaklar systemd gibi kaldirilir.
"""

import os
from pathlib import Path

SYSTEM_DIR = Path("/etc/metehantech-status")
USER_DIR = Path.home() / ".config" / "metehantech-status"


def candidates(filename):
    """Aranacak yollar, oncelik sirasiyla.

    METEHANTECH_CONFIG_DIR tanimliysa MUNHASIRDIR: yalnizca o dizine bakilir.
    Boylece testler ve yalitimli calistirmalar makinenin gercek yapilandirmasini
    yanlislikla okuyamaz.
    """
    override = os.environ.get("METEHANTECH_CONFIG_DIR", "").strip()
    if override:
        return [Path(override) / filename]
    return [SYSTEM_DIR / filename, USER_DIR / filename]


def parse(text):
    values = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if key:
            values[key] = value
    return values


def load(filename):
    """Ilk okunabilir adaydaki degerleri dondur. Hicbiri yoksa bos sozluk."""
    for path in candidates(filename):
        try:
            return parse(path.read_text(encoding="utf-8"))
        except (FileNotFoundError, PermissionError, IsADirectoryError, OSError):
            continue
    return {}
