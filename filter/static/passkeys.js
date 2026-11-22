/* spamfilter 2.6 - passkeys (WebAuthn). Loaded per page
   (<script src defer>), CSP-clean (no inline code).

     [data-passkey-login-box]   login page: "Log ind med passkey"
                                (discoverable credential, user verification)
     [data-passkey-add]         Min konto: name + "Tilføj passkey"
     [data-passkey-unsupported] shown instead when the browser cannot

   The server decides where passkeys work (https external address or
   localhost) and verifies everything; this file only moves bytes between
   navigator.credentials and the JSON endpoints.
*/
(function () {
  "use strict";

  function $(sel, root) { return (root || document).querySelector(sel); }
  function $$(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }

  function csrf() {
    var m = $('meta[name="csrf-token"]');
    if (m) return m.getAttribute("content") || "";
    var i = $('input[name="csrf"]');
    return i ? i.value : "";
  }

  function toast(kind, title, detail) {
    if (window.SF && window.SF.toast) window.SF.toast(kind, title, detail || "");
  }

  function b64ToBuf(s) {
    s = String(s || "").replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    var bin = atob(s), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  }

  function bufToB64(buf) {
    if (!buf) return null;
    var bytes = new Uint8Array(buf), bin = "";
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function post(url, body) {
    return fetch(url, {
      method: "POST", credentials: "same-origin",
      headers: { "Accept": "application/json", "Content-Type": "application/json", "X-CSRF-Token": csrf(),
                 "X-Requested-With": "fetch" },
      body: JSON.stringify(body || {})
    }).then(function (res) {
      return res.json().catch(function () {
        return { ok: false, message: res.status === 400 ? "Siden er forældet – genindlæs den, og prøv igen."
                                                        : "Uventet svar fra spamfilteret (" + res.status + ")." };
      });
    });
  }

  var supported = !!(window.PublicKeyCredential && window.isSecureContext && navigator.credentials);

  function cancelled(err) {
    return err && (err.name === "NotAllowedError" || err.name === "AbortError");
  }

  function busy(btn, on) {
    if (!btn) return;
    btn.disabled = !!on;
    btn.classList.toggle("is-loading", !!on);
    if (on) btn.setAttribute("aria-busy", "true"); else btn.removeAttribute("aria-busy");
  }

  // ---------------------------------------------------------------- login
  var box = $("[data-passkey-login-box]");
  if (box) {
    if (!supported) {
      $$("[data-passkey-unsupported]").forEach(function (n) { n.hidden = false; });
    } else {
      box.hidden = false;
      var btn = $("[data-passkey-login]", box);
      btn.addEventListener("click", function () {
        var next = box.getAttribute("data-next") || "/";
        var remember = $('input[name="remember"]');
        busy(btn, true);
        post("/login/passkey/options").then(function (data) {
          if (!data || !data.ok) throw { message: (data && data.message) || "Passkeys virker ikke lige nu." };
          var pk = data.publicKey;
          return navigator.credentials.get({ publicKey: {
            challenge: b64ToBuf(pk.challenge), rpId: pk.rpId, timeout: pk.timeout,
            userVerification: pk.userVerification, allowCredentials: [] } });
        }).then(function (cred) {
          if (!cred) throw { message: "Ingen passkey valgt." };
          var r = cred.response;
          return post("/login/passkey?next=" + encodeURIComponent(next), {
            id: cred.id, rawId: bufToB64(cred.rawId), type: cred.type,
            remember: !!(remember && remember.checked),
            response: { clientDataJSON: bufToB64(r.clientDataJSON), authenticatorData: bufToB64(r.authenticatorData),
                        signature: bufToB64(r.signature), userHandle: bufToB64(r.userHandle) } });
        }).then(function (data) {
          if (data && data.ok) { location.href = data.redirect || "/"; return; }
          if (data && data.code === "unknown" && window.PublicKeyCredential.signalUnknownCredential) {
            // WebAuthn L3: let the device forget a passkey the server no longer knows.
            window.PublicKeyCredential.signalUnknownCredential({ rpId: data.rp, credentialId: data.credential })
              .catch(function () {});
          }
          busy(btn, false);
          toast("bad", "Log ind med passkey mislykkedes", (data && data.message) || "");
        }).catch(function (err) {
          busy(btn, false);
          if (cancelled(err)) return;
          toast("bad", "Log ind med passkey mislykkedes", (err && err.message) || "Prøv igen – eller brug adgangskoden.");
        });
      });
    }
  }

  // ---------------------------------------------------------------- Min konto: add
  var add = $("[data-passkey-add]");
  if (add) {
    if (!supported) {
      $$("[data-passkey-unsupported]").forEach(function (n) { n.hidden = false; });
    } else {
      add.hidden = false;
      var create = $("[data-passkey-create]", add);
      create.addEventListener("click", function () {
        var label = ($("#pk-label") || {}).value || "";
        busy(create, true);
        post("/me/passkeys/options").then(function (data) {
          if (!data || !data.ok) {
            if (data && data.redirect) { location.href = data.redirect; return null; }
            throw { message: (data && data.message) || "Passkeys virker ikke lige nu." };
          }
          var pk = data.publicKey;
          pk.challenge = b64ToBuf(pk.challenge);
          pk.user.id = b64ToBuf(pk.user.id);
          pk.excludeCredentials = (pk.excludeCredentials || []).map(function (c) {
            return { type: c.type, id: b64ToBuf(c.id) };
          });
          return navigator.credentials.create({ publicKey: pk });
        }).then(function (cred) {
          if (cred === null) return null;
          if (!cred) throw { message: "Der blev ikke lavet nogen passkey." };
          var r = cred.response;
          return post("/me/passkeys/register", {
            id: cred.id, rawId: bufToB64(cred.rawId), type: cred.type, label: label,
            response: { clientDataJSON: bufToB64(r.clientDataJSON), attestationObject: bufToB64(r.attestationObject),
                        transports: r.getTransports ? r.getTransports() : [] } });
        }).then(function (data) {
          if (data === null || data === undefined) return;
          busy(create, false);
          if (data.ok) {
            toast("ok", data.message || "Passkeyen er gemt.");
            setTimeout(function () { location.href = data.redirect || "/me"; location.reload(); }, 600);
            return;
          }
          if (data.redirect) { location.href = data.redirect; return; }
          toast("bad", "Passkeyen blev ikke gemt", data.message || "");
        }).catch(function (err) {
          busy(create, false);
          if (err && err.name === "InvalidStateError") {
            toast("warn", "Denne enhed har allerede en passkey til spamfilteret.");
            return;
          }
          if (cancelled(err)) return;
          toast("bad", "Passkeyen blev ikke gemt", (err && err.message) || "Prøv igen.");
        });
      });
    }
  }
})();
