// Service Worker for Commission Tracker PWA
// Strategy: Network-first with offline fallback
// We don't aggressively cache pages since data is always fresh from the DB,
// but we cache static assets and provide a basic offline page.

const CACHE_NAME = 'ct-v1';
const STATIC_ASSETS = [
  '/static/icon-192.png',
  '/static/icon-512.png',
];

// Install: pre-cache static assets
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(STATIC_ASSETS))
  );
  self.skipWaiting();
});

// Activate: clean up old caches
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((names) =>
      Promise.all(names.filter((n) => n !== CACHE_NAME).map((n) => caches.delete(n)))
    )
  );
  self.clients.claim();
});

// Fetch: network-first for pages, cache-first for static assets
self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  // Cache-first for static assets
  if (url.pathname.startsWith('/static/')) {
    event.respondWith(
      caches.match(event.request).then((cached) => cached || fetch(event.request))
    );
    return;
  }

  // Network-first for everything else (pages need fresh data)
  // If offline, show a simple fallback
  if (event.request.mode === 'navigate') {
    event.respondWith(
      fetch(event.request).catch(() =>
        new Response(
          '<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Offline</title>' +
          '<style>body{font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#f8fafc;text-align:center;padding:2rem}' +
          'h1{font-size:1.25rem;color:#0f172a;margin-bottom:.5rem}p{color:#64748b;font-size:.9rem}button{margin-top:1.5rem;padding:.5rem 1.5rem;border-radius:.5rem;background:#0f172a;color:#fff;border:none;cursor:pointer;font-size:.9rem}</style></head>' +
          '<body><div><h1>You\'re offline</h1><p>Check your connection and try again.</p><button onclick="location.reload()">Retry</button></div></body></html>',
          { headers: { 'Content-Type': 'text/html' } }
        )
      )
    );
    return;
  }
});
