/**
 * CyberShield AI — Service Worker v2
 * Offline caching + Push Notifications + Background alerts
 */
const CACHE = 'cybershield-v2';
const ASSETS = ['./', './index.html', './style.css', './app.js', './manifest.json',
  './icons/icon-192.png', './icons/icon-512.png',
  'https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(ASSETS).catch(() => {})));
  self.skipWaiting();
});

self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== CACHE).map(k => caches.delete(k)))));
  self.clients.claim();
});

self.addEventListener('fetch', e => {
  if (e.request.method !== 'GET') return;
  e.respondWith(
    caches.match(e.request).then(cached => {
      if (cached) return cached;
      return fetch(e.request).then(r => {
        if (r && r.status === 200) {
          const clone = r.clone();
          caches.open(CACHE).then(c => c.put(e.request, clone));
        }
        return r;
      }).catch(() => e.request.mode === 'navigate' ? caches.match('./index.html') : undefined);
    })
  );
});

self.addEventListener('push', e => {
  let d = { title: '⚠️ CyberShield Alert', body: 'Fraud detected!', risk: 'high' };
  try { d = e.data.json(); } catch {}
  e.waitUntil(self.registration.showNotification(d.title, {
    body: d.body, icon: './icons/icon-192.png', badge: './icons/icon-72.png',
    tag: 'cs-' + Date.now(), renotify: true,
    requireInteraction: d.risk === 'high',
    vibrate: d.risk === 'high' ? [300,100,300,100,500] : [200,100,200],
    actions: [{ action: 'view', title: '🔍 View Alert' }, { action: 'dismiss', title: '✕ Dismiss' }],
    data: { risk: d.risk }
  }));
});

self.addEventListener('notificationclick', e => {
  e.notification.close();
  if (e.action === 'dismiss') return;
  e.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(clients => {
      const c = clients.find(c => c.url.includes('index.html'));
      if (c) { c.focus(); c.postMessage({ type: 'NAVIGATE', tab: 'history' }); }
      else self.clients.openWindow('./index.html?tab=history');
    })
  );
});

self.addEventListener('message', e => {
  if (e.data?.type === 'SHOW_NOTIFICATION') {
    const { title, body, risk } = e.data;
    self.registration.showNotification(title, {
      body, icon: './icons/icon-192.png', badge: './icons/icon-72.png',
      tag: 'cs-' + Date.now(), renotify: true, requireInteraction: risk === 'high',
      vibrate: risk === 'high' ? [300,100,300,100,500] : [200,100,200],
      data: { risk }
    });
  }
});
