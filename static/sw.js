/* MetehanTech Control Center service worker.
 *
 * Gizlilik kurali: burada YALNIZCA /static/ altindaki kamuya acik varliklar
 * onbellege alinir. Gezinme yanitlari (HTML) ve /api/ yanitlari asla
 * onbellege yazilmaz; oturum acmis kullanicinin verisi diskte kalmasin diye.
 * Servis calisanin tek isi uygulamanin kurulabilir olmasi ve varlik yuklemesinin
 * hizlanmasidir, veri ikizlemesi degil.
 *
 * Bu dosyayi degistirdiginde VERSION'u artir; eski onbellekler activate'te silinir.
 */

const VERSION = "mt-pwa-1";
const ASSET_CACHE = `${VERSION}-assets`;
const OFFLINE_URL = "/static/offline.html";

const PRECACHE = [
  OFFLINE_URL,
  "/static/icons/icon-192.png",
  "/static/icons/icon-512.png",
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches
      .open(ASSET_CACHE)
      .then((cache) => cache.addAll(PRECACHE))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) =>
        Promise.all(keys.filter((key) => key !== ASSET_CACHE).map((key) => caches.delete(key)))
      )
      .then(() => self.clients.claim())
  );
});

function isCacheableAsset(url) {
  return url.origin === self.location.origin && url.pathname.startsWith("/static/");
}

self.addEventListener("fetch", (event) => {
  const request = event.request;
  if (request.method !== "GET") return;

  const url = new URL(request.url);

  // Gezinme: her zaman ag. Basarisizsa yalnizca cevrimdisi kabugu don.
  if (request.mode === "navigate") {
    event.respondWith(
      fetch(request).catch(() =>
        caches.match(OFFLINE_URL).then((cached) => cached || Response.error())
      )
    );
    return;
  }

  if (!isCacheableAsset(url)) return; // /api/ dahil her sey dogrudan aga gider.

  // Varliklar surum sorgusuyla (?v=...) adreslenir; onbellek-once guvenli.
  event.respondWith(
    caches.match(request).then((cached) => {
      const network = fetch(request)
        .then((response) => {
          if (response && response.ok && response.type === "basic") {
            const copy = response.clone();
            caches.open(ASSET_CACHE).then((cache) => cache.put(request, copy));
          }
          return response;
        })
        .catch(() => cached || Response.error());
      return cached || network;
    })
  );
});
