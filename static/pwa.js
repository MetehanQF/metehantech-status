/* Servis calisan kaydi. CSP 'default-src self' oldugu icin satir ici script
 * calismaz; kayit bu ayri dosyadan yapilir. */
(function registerServiceWorker() {
  if (!("serviceWorker" in navigator)) return;
  window.addEventListener("load", function () {
    navigator.serviceWorker.register("/sw.js", { scope: "/" }).catch(function (error) {
      console.warn("Service worker kaydedilemedi:", error);
    });
  });
})();
