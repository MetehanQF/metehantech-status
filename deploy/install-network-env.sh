#!/bin/bash
# metehantech-status — ag yapilandirmasi kurulumu
#
# Calistirma:  sudo bash <proje-kokü>/deploy/install-network-env.sh
#
# NE YAPAR (hepsi eklemeli; mevcut yapilandirma korunur):
#   1. /etc/metehantech-status/network.env            (YENI, root:root 0600)
#   2. /etc/systemd/system/metehantech-status.service.d/10-network-env.conf  (YENI drop-in)
#   3. systemd-analyze verify + daemon-reload
#
# NE YAPMAZ:
#   - Mevcut metehantech-status.service birimini DEGISTIRMEZ (drop-in kullanir).
#   - Mevcut /etc/metehantech-status/admin.env dosyasina DOKUNMAZ.
#   - Servisi yeniden BASLATMAZ. Restart'i ayrica ve kontrollu yapin:
#       sudo -n /usr/bin/systemctl restart --no-block metehantech-status.service
#     (ASLA SIGHUP/reload kullanmayin: collector flock'u bir kez dener ve kaybolur.)
#
# DEGERLER BU BETIKTE SABIT DEGILDIR. Gercek adresler Git disi bir kaynak
# dosyadan okunur; boylece bu betik repoya girse bile ev agini ifsa etmez:
#     deploy/network.env         (varsayilan kaynak, .gitignore: *.env)
#     veya ilk argumanla verilen yol:  sudo bash install-network-env.sh /yol/dosya
# Sablon: ../network.env.example  (yalnizca RFC dokumantasyon adresleri)

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "HATA: root olarak calistirin:  sudo bash $0" >&2
  exit 1
fi

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
SOURCE_ENV=${1:-$SCRIPT_DIR/network.env}
SOURCE_DEPLOY=${2:-$SCRIPT_DIR/deploy.env}

for pair in "network.env:$SOURCE_ENV" "deploy.env:$SOURCE_DEPLOY"; do
  name=${pair%%:*}; file=${pair#*:}
  if [ ! -f "$file" ]; then
    echo "HATA: kaynak deger dosyasi bulunamadi: $file" >&2
    echo "  Olusturmak icin:" >&2
    echo "    cp $SCRIPT_DIR/../${name}.example $SCRIPT_DIR/$name" >&2
    echo "    chmod 600 $SCRIPT_DIR/$name && nano $SCRIPT_DIR/$name" >&2
    echo "  (Bu betikte gercek deger fallback'i bilerek birakilmamistir.)" >&2
    exit 1
  fi
done

# Kaynak dosyalarda zorunlu anahtarlarin hepsi var mi
MISSING=""
for key in PI5_LAN_IP PCOLD_LAN_IP CAMERA_LAN_IP PI5_TAILSCALE_IP PCOLD_TAILSCALE_IP; do
  grep -qE "^${key}=.+" "$SOURCE_ENV" || MISSING="$MISSING $key"
done
for key in BACKUP_REMOTE_USER BACKUP_SSH_KEY DNS_CREDENTIALS; do
  grep -qE "^${key}=.+" "$SOURCE_DEPLOY" || MISSING="$MISSING $key"
done
if [ -n "$MISSING" ]; then
  echo "HATA: $SOURCE_ENV icinde eksik/bos anahtar:$MISSING" >&2
  exit 1
fi

CFG_DIR=/etc/metehantech-status
CFG=$CFG_DIR/network.env
DEPLOY_CFG=$CFG_DIR/deploy.env
DROPIN_DIR=/etc/systemd/system/metehantech-status.service.d
DROPIN=$DROPIN_DIR/10-network-env.conf
STAMP=$(date -u +%Y%m%dT%H%M%SZ)

echo "=== ONCESI DURUM ==="
echo -n "  $CFG: ";        [ -f "$CFG" ]        && echo "VAR (yedeklenecek)" || echo "yok"
echo -n "  $DEPLOY_CFG: "; [ -f "$DEPLOY_CFG" ] && echo "VAR (yedeklenecek)" || echo "yok"
echo -n "  $DROPIN: ";     [ -f "$DROPIN" ]     && echo "VAR (yedeklenecek)" || echo "yok"
# is-active servis calismiyorsa sifir disi doner; pipefail altinda bu betigi
# oldururdu. Durumu bilgi olarak istiyoruz, cikis kosulu olarak degil.
echo "  servis: $(systemctl is-active metehantech-status.service 2>/dev/null || true)"

# --- mevcut dosyalari yedekle -------------------------------------------------
for f in "$CFG" "$DEPLOY_CFG" "$DROPIN"; do
  [ -f "$f" ] && cp -p "$f" "$f.bak-$STAMP" && echo "  yedek: $f.bak-$STAMP"
done

# --- 1. network.env -----------------------------------------------------------
install -d -m 0755 -o root -g root "$CFG_DIR"
{
  echo "# metehantech-status — ortam bagimli ag adresleri"
  echo "# Bu dosya repo DISINDADIR ve Git'e girmez."
  echo "# Kaynak: $SOURCE_ENV"
  echo "# Sablon: $SCRIPT_DIR/../network.env.example"
  echo "# Uretildi: $STAMP"
  echo
  # Yalnizca KEY=VALUE satirlari aktarilir; yorum ve bos satirlar atilir.
  grep -E '^[A-Z][A-Z0-9_]*=' "$SOURCE_ENV"
} > "$CFG"
chown root:root "$CFG"
# 0600: yalnizca root okur. systemd EnvironmentFile'i root olarak, ayricaliklari
# birakmadan once yukler; servis User=metehanqf olsa da degerleri gorur.
# Sonuc: net-switch-usb-only.sh gibi normal kullanici betikleri bu dosyayi
# OKUYAMAZ ve "sudo ile calistirin" hatasi verir. Bilincli tercih.
chmod 0600 "$CFG"

# --- 1b. deploy.env -----------------------------------------------------------
{
  echo "# metehantech-status — deployment'a ozel yollar ve hesaplar"
  echo "# Bu dosya repo DISINDADIR ve Git'e girmez."
  echo "# Kaynak: $SOURCE_DEPLOY"
  echo "# Sablon: $SCRIPT_DIR/../deploy.env.example"
  echo "# Uretildi: $STAMP"
  echo
  grep -E '^[A-Z][A-Z0-9_]*=' "$SOURCE_DEPLOY"
} > "$DEPLOY_CFG"
chown root:root "$DEPLOY_CFG"
chmod 0600 "$DEPLOY_CFG"

# --- 2. systemd drop-in (ana birim DEGISMEZ) ----------------------------------
install -d -m 0755 -o root -g root "$DROPIN_DIR"
cat > "$DROPIN" <<'UNITEOF'
# metehantech_status ag yapilandirmasini yukler.
# Ana birim dosyasi (metehantech-status.service) bilerek degistirilmemistir.
[Service]
EnvironmentFile=-/etc/metehantech-status/network.env
EnvironmentFile=-/etc/metehantech-status/deploy.env
UNITEOF
chown root:root "$DROPIN"
chmod 0644 "$DROPIN"

# --- 3. dogrulama -------------------------------------------------------------
echo
echo "=== DOGRULAMA ==="
echo "--- izinler ---"
stat -c '  %n  %A  %U:%G' "$CFG" "$DEPLOY_CFG" "$DROPIN"

echo "--- anahtarlar (yalnizca ISIMLER; degerler basilmaz) ---"
grep -hoE '^[A-Z][A-Z0-9_]*' "$CFG" "$DEPLOY_CFG" | sed 's/^/  /' || true
echo "  (toplam $(grep -hcE '^[A-Z]' "$CFG" "$DEPLOY_CFG" | paste -sd+ | bc) anahtar ayarlandi)"

# daemon-reload ONCE: yoksa systemd-analyze verify yeni drop-in'i gormez.
systemctl daemon-reload

echo "--- systemd-analyze verify ---"
verify_out=$(systemd-analyze verify metehantech-status.service 2>&1 || true)
if [ -z "$verify_out" ]; then
  echo "  temiz (uyari yok)"
else
  printf '%s\n' "$verify_out" | sed 's/^/  /'
fi

echo "--- drop-in birime islendi mi ---"
systemctl show metehantech-status.service -p EnvironmentFiles | sed 's/^/  /'

echo
echo "=== TAMAM ==="
echo "Servis HENUZ yeniden baslatilmadi. Sirasi geldiginde:"
echo "  sudo -n /usr/bin/systemctl restart --no-block metehantech-status.service"
