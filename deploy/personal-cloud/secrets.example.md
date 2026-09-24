# personal-cloud — gerekli Docker secret dosyalari

`compose.yaml` hicbir paroleyi satir ici tutmaz; hepsini Docker secrets ile
`/run/secrets/<ad>` altindan okur. Kaynak dosyalar **repo disinda** durur:

```
/etc/metehantech-cloud/secrets/
```

Bu dizin bilerek repo disindadir; asla repoya kopyalanmaz.

## Gerekli dosyalar

| Secret adi                 | Dosya yolu                                              | Icerik |
|----------------------------|---------------------------------------------------------|--------|
| `postgres_password`        | `/etc/metehantech-cloud/secrets/postgres-password`        | Postgres `nextcloud` kullanicisinin parolasi |
| `redis_password`           | `/etc/metehantech-cloud/secrets/redis-password`           | Redis AUTH parolasi |
| `redis_acl`                | `/etc/metehantech-cloud/secrets/redis.acl`                | Redis ACL kural dosyasi |
| `nextcloud_admin_user`     | `/etc/metehantech-cloud/secrets/nextcloud-admin-user`     | Nextcloud admin kullanici adi |
| `nextcloud_admin_password` | `/etc/metehantech-cloud/secrets/nextcloud-admin-password` | Nextcloud admin parolasi |

## Ilk kurulum

```bash
sudo install -d -m 0750 -o root -g docker /etc/metehantech-cloud/secrets

# Her parola icin (ornek: postgres)
python3 -c "import secrets; print(secrets.token_urlsafe(32))" \
  | sudo tee /etc/metehantech-cloud/secrets/postgres-password >/dev/null
sudo chmod 0640 /etc/metehantech-cloud/secrets/postgres-password
sudo chown root:docker /etc/metehantech-cloud/secrets/postgres-password
```

Sondaki satir sonu onemlidir: dosyanin sonunda `\n` kalirsa bazi imajlar onu
parolanin parcasi sayar. `printf '%s' "$PAROLA"` ile yazmak daha guvenlidir.

## Dogrulama

```bash
# Dosyalar yerinde ve izinleri dogru mu
sudo ls -l /etc/metehantech-cloud/secrets/

# Container secret'i gorebiliyor mu (deger yazdirmadan, yalnizca boyut)
docker exec metehantech-cloud-db stat -c '%s bayt' /run/secrets/postgres_password
```

## Parola degistirme

Secret dosyasini degistirmek tek basina yetmez — Docker secrets container
baslangicinda okunur ve ilgili servisteki parola ayrica guncellenmelidir
(Postgres icin `ALTER ROLE`, Nextcloud icin `occ user:resetpassword`).
Once servis icindeki parolayi degistirin, sonra dosyayi guncelleyip
`docker compose up -d` ile yeniden yaratın.
