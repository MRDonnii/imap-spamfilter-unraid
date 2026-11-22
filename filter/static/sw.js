/* spamfilter — service worker (served as /sw.js, scope "/").

   Deliberately minimal and privacy-safe:
     * caches ONLY the versioned static assets (/static/...) and the public
       /offline page;
     * NEVER caches pages, JSON or anything else that needs a login: every
       navigation goes to the network, and only when the network fails is
       the offline page shown instead;
     * POST and cross-origin requests are not touched at all.
   The server fills in VERSION and ASSETS (cache-busting tag), so every
   asset change installs a new worker that deletes the old cache.

   2.5.0 push notifications ("Beskeder på denne enhed"): a 'push' event
   shows the notification from the encrypted payload {title, body, url,
   tag} (counts and mailbox names only - never a subject or a sender);
   'notificationclick' focuses the app (or opens it) on the payload's URL,
   which must be a path of THIS origin - anything else opens "/". */
"use strict";

var VERSION = __SF_VERSION__;
var ASSETS = __SF_ASSETS__;
var CACHE = "sf-static-" + VERSION;
var OFFLINE = "/offline";

self.addEventListener("install", function (event) {
  event.waitUntil(
    caches.open(CACHE).then(function (cache) {
      return cache.addAll(ASSETS.concat([OFFLINE]));
    }).then(function () { return self.skipWaiting(); })
  );
});

self.addEventListener("activate", function (event) {
  event.waitUntil(
    caches.keys().then(function (keys) {
      return Promise.all(keys.filter(function (k) {
        return k.indexOf("sf-static-") === 0 && k !== CACHE;
      }).map(function (k) { return caches.delete(k); }));
    }).then(function () { return self.clients.claim(); })
  );
});

function isStaticAsset(url) {
  return url.origin === self.location.origin && url.pathname.indexOf("/static/") === 0;
}

self.addEventListener("fetch", function (event) {
  var req = event.request;
  if (req.method !== "GET") return;
  var url = new URL(req.url);
  if (url.origin !== self.location.origin) return;

  if (req.mode === "navigate") {
    // Network only; the (public) offline page is the fallback. Logged-in
    // HTML is never stored.
    event.respondWith(
      fetch(req).catch(function () {
        return caches.match(OFFLINE).then(function (r) {
          return r || new Response("Offline", { status: 503, headers: { "Content-Type": "text/plain; charset=utf-8" } });
        });
      })
    );
    return;
  }

  if (isStaticAsset(url)) {
    // Versioned, immutable assets: cache first.
    event.respondWith(
      caches.open(CACHE).then(function (cache) {
        return cache.match(req).then(function (hit) {
          if (hit) return hit;
          return fetch(req).then(function (res) {
            if (res && res.ok && res.type === "basic") cache.put(req, res.clone());
            return res;
          });
        });
      })
    );
  }
  // Everything else (JSON, fragments, /api/...): straight to the network.
});

// ---------------------------------------------------------------- push (2.5.0)
var ICON = ASSETS.filter(function (a) { return a.indexOf("/static/icon-192.png") === 0; })[0] || "/static/icon-192.png";

// Only a same-origin path ("/spam?account=x") is ever opened; "//host",
// "https://other", "javascript:" and friends all become "/".
function safePath(value) {
  if (typeof value !== "string" || value.charAt(0) !== "/" || value.charAt(1) === "/" || value.charAt(1) === "\\") return "/";
  try {
    var u = new URL(value, self.location.origin);
    if (u.origin !== self.location.origin) return "/";
    return u.pathname + u.search + u.hash;
  } catch (e) {
    return "/";
  }
}

function text(value, max, fallback) {
  return (typeof value === "string" && value) ? value.slice(0, max) : fallback;
}

self.addEventListener("push", function (event) {
  var d = {};
  try { d = event.data ? event.data.json() : {}; } catch (e) { d = {}; }
  if (!d || typeof d !== "object") d = {};
  var title = text(d.title, 80, "Spamfilter");
  var tag = /^[a-z0-9-]{1,32}$/.test(d.tag || "") ? d.tag : "sf";
  // iOS revokes a subscription that receives pushes without a visible
  // notification, so there is always one - even for an unreadable payload.
  event.waitUntil(self.registration.showNotification(title, {
    body: text(d.body, 180, "Åbn spamfilteret for at se mere."),
    tag: tag,
    renotify: true,
    icon: ICON,
    badge: ICON,
    lang: "da",
    data: { url: safePath(d.url) }
  }));
});

self.addEventListener("notificationclick", function (event) {
  event.notification.close();
  var path = safePath(event.notification.data && event.notification.data.url);
  var target = new URL(path, self.location.origin).href;
  event.waitUntil(
    self.clients.matchAll({ type: "window", includeUncontrolled: true }).then(function (list) {
      for (var i = 0; i < list.length; i++) {
        var c = list[i];
        if (new URL(c.url).origin !== self.location.origin || !("focus" in c)) continue;
        return c.focus().then(function (fc) {
          var w = fc || c;
          return ("navigate" in w) ? w.navigate(target).catch(function () { return w; }) : w;
        });
      }
      return self.clients.openWindow ? self.clients.openWindow(target) : null;
    })
  );
});
