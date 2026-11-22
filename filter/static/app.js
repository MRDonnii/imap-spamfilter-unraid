/* spamfilter 2.0 — progressive enhancement (no dependencies).
   Loaded synchronously in <head> so the theme is applied before first
   paint; everything else waits for DOMContentLoaded.

   Hooks (all optional, pages work without JS):
     form[data-ajax]              submit with fetch(), JSON reply -> toasts
                                  reply keys: ok, message, results[], rows{key: html|null},
                                  reload (config change: restart overlay), refresh, redirect,
                                  undo {label, url, fields} -> "Fortryd" button in the toast
                                  actions [{label, url, fields}] -> more toast buttons (2.3: "Behold som kontakt")
                                  confirm {title, text, label, tone, url, fields} -> the server needs a
                                  confirmation first (2.3: release of a dangerous mail); OK posts fields
     form[data-sync]              also posts sync=<key> for every [data-row] sharing the
                                  clicked row's data-sync-key (same sender domain), so the
                                  server can re-render all of them after a rule change
     [data-confirm]               modal confirm before submit (on button or form);
                                  data-confirm-text/-label/-tone, data-confirm-typed="FJERN"
     form[data-bulk]              bulk selection (checkboxes with form="<id>" name="items")
     [data-select-all="<id>"]     select-all checkbox for that bulk form
     [data-bulkbar="<id>"]        sticky bar shown while something is selected
     form[data-autosubmit]        GET filter forms: selects submit on change
     [data-live="key"]            refreshed from /api/status every 15 s
     [data-fragment="/url"]       lazy HTML fragment (replaces a skeleton)
     [data-reload-after="s"]      (2.10) reload the page after s seconds (Opdateringer while
                                  an update waits/runs); not while you type or a dialog is open
     [data-open-modal="id"]       open <dialog id>; [data-close-modal] closes
     dialog[data-auto-open]       (2.11) rendered open -> real modal on load (new API key, shown once)
     [data-needs-check="id"]      (2.11) link disabled until checkbox #id is ticked
     [data-copy="text"]           copy to clipboard
     [data-nav-toggle]            (2.8.1) fold the sidebar to an icon rail (html.nav-mini, localStorage, Ctrl/Cmd+B)
     [data-skin-set] [data-navpos-set] [data-theme-set]  (2.10) Udseende: style, menu placement, theme
     [data-href="/url"]           whole row clickable
     input[data-rule-preview]     live rule preview (/rules/preview)
     input[type=range][data-range-output="id"]  mirrors the value (Danish comma)
     input[data-switch-submit]    switch that submits its form on change (2.3)
     [data-copy-text] [data-download-text] input[data-otp] [data-install] [data-offline]
                                  two-step login + app on the phone (see initCodes/initOtp/initInstall)
     button[data-countdown="N"]    resend cooldown: disabled + live countdown (2.3)
     reply.dialog {title, html}   (2.3 rules dialog) a Bloker/Tillad button posted choose=1: the
                                  server sends the "Kun denne adresse / Hele domænet" dialog
                                  (server-rendered, escaped HTML); it closes after a good result
     input[data-rule-choices="id"] (2.3) Regler form: the same two choices, refreshed from
                                  /rules/preview?form=1 (+ data-rule-existing="id": existing rules)
     li[data-swipe-right] / li[data-swipe-left]  (2.5.0) touch swipe on a mail row: right = Frigiv,
                                  left = Det er spam. The attribute (label) exists only for an action
                                  the server allows on that row; the row holds the matching
                                  form[data-swipe-form="right|left"] (button form or a hidden one)
     [data-push]                  (2.5.0) Min konto -> "Beskeder på denne enhed": initPush() checks
                                  secure context + service worker + PushManager, shows the matching
                                  [data-push-why] text, or [data-push-off] / [data-push-on];
                                  [data-push-enable] asks for permission (user gesture) and
                                  subscribes with the VAPID key from data-push-key-url;
                                  [data-push-disable] unsubscribes; li[data-push-hash] = a device
     window.SF.{toast, confirm, restart, submit, ruleDialog}
*/
(function () {
  "use strict";
  var KEY = "sf-theme";
  // 2.10 (Fleetdeck-design): style and menu placement, like Fleetdeck's own
  // "Udseende" (fd-skin / fd-nav). Stored in this browser; default = Command,
  // dark theme, menu in the side.
  var SKIN_KEY = "sf-skin", NAVPOS_KEY = "sf-nav";
  var root = document.documentElement;
  var mq = window.matchMedia ? window.matchMedia("(prefers-color-scheme: light)") : null;
  // theme-color (browser chrome / PWA title bar) = the page background of each style.
  var BG = { command: { dark: "#0b0b0d", light: "#f7f7f8" }, aurora: { dark: "#070b16", light: "#f3f5fb" } };

  function stored(key, fallback, allowed) {
    var v = null;
    try { v = localStorage.getItem(key); } catch (e) { /* private mode */ }
    return allowed.indexOf(v) >= 0 ? v : fallback;
  }
  function storedTheme() { return stored(KEY, "dark", ["dark", "light", "system"]); }
  function storedSkin() { return stored(SKIN_KEY, "command", ["command", "aurora"]); }
  function storedNav() { return stored(NAVPOS_KEY, "side", ["side", "top"]); }
  function resolve(pref) {
    if (pref === "system") return mq && mq.matches ? "light" : "dark";
    return pref === "light" ? "light" : "dark";
  }
  // Every [data-theme-set] / [data-skin-set] / [data-navpos-set] shows whether it is the current choice.
  function syncLook() {
    var cur = { "data-theme-set": storedTheme(), "data-skin-set": storedSkin(), "data-navpos-set": storedNav() };
    Object.keys(cur).forEach(function (attr) {
      Array.prototype.forEach.call(document.querySelectorAll("[" + attr + "]"), function (b) {
        b.setAttribute("aria-pressed", b.getAttribute(attr) === cur[attr] ? "true" : "false");
      });
    });
  }
  function applyTheme(pref) {
    var t = resolve(pref), bg = BG[storedSkin()];
    root.setAttribute("data-theme", t);
    // Two media-specific theme-color tags: "system" restores each to its
    // own colour, a forced theme sets both.
    Array.prototype.forEach.call(document.querySelectorAll('meta[name="theme-color"]'), function (m) {
      var own = /light/.test(m.getAttribute("media") || "") ? bg.light : bg.dark;
      m.setAttribute("content", pref === "system" ? own : bg[t]);
    });
    syncLook();
  }
  function applyLook() {
    root.setAttribute("data-skin", storedSkin());
    root.setAttribute("data-nav", storedNav());
  }
  applyLook();
  applyTheme(storedTheme());
  root.classList.add("js");
  // 2.8.1: folded sidebar (icon rail), applied before first paint (this file
  // is a blocking <script> in <head>, so no flash of the wide menu). Shared
  // key name across the apps (2026-11-21): <app>.nav.collapsed; the old
  // sf-nav-mini value is carried over once.
  var NAV_KEY = "spamfilter.nav.collapsed", NAV_OLD_KEY = "sf-nav-mini";
  try {
    var navOld = localStorage.getItem(NAV_OLD_KEY);
    if (navOld !== null) {
      if (localStorage.getItem(NAV_KEY) === null) localStorage.setItem(NAV_KEY, navOld === "1" ? "1" : "0");
      localStorage.removeItem(NAV_OLD_KEY);
    }
    if (localStorage.getItem(NAV_KEY) === "1") root.classList.add("nav-mini");
  } catch (e) { /* private mode */ }
  if (mq && mq.addEventListener) mq.addEventListener("change", function () { if (storedTheme() === "system") applyTheme("system"); });

  var SF = window.SF = {};
  SF.setTheme = function (pref) {
    try { localStorage.setItem(KEY, pref); } catch (e) { /* private mode */ }
    applyTheme(pref);
  };
  SF.getTheme = storedTheme;
  SF.setSkin = function (skin) {
    try { localStorage.setItem(SKIN_KEY, skin === "aurora" ? "aurora" : "command"); } catch (e) { /* private mode */ }
    applyLook(); applyTheme(storedTheme());
  };
  SF.setNavPos = function (pos) {
    try { localStorage.setItem(NAVPOS_KEY, pos === "top" ? "top" : "side"); } catch (e) { /* private mode */ }
    applyLook(); syncLook();
  };

  // ---------------------------------------------------------------- helpers
  function $(sel, ctx) { return (ctx || document).querySelector(sel); }
  function $$(sel, ctx) { return Array.prototype.slice.call((ctx || document).querySelectorAll(sel)); }
  function csrf() { var m = $('meta[name="csrf-token"]'); return m ? m.getAttribute("content") : ""; }
  function sprite() {
    var u = $("use");
    var href = u ? (u.getAttribute("href") || "") : "";
    return href.split("#")[0] || "/static/icons.svg";
  }
  function icon(name, cls) {
    var ns = "http://www.w3.org/2000/svg";
    var svg = document.createElementNS(ns, "svg");
    svg.setAttribute("class", "icon" + (cls ? " " + cls : ""));
    svg.setAttribute("aria-hidden", "true");
    var use = document.createElementNS(ns, "use");
    use.setAttribute("href", sprite() + "#i-" + name);
    svg.appendChild(use);
    return svg;
  }
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }
  function nonce() {
    if (window.crypto && crypto.getRandomValues) {
      var a = new Uint8Array(18); crypto.getRandomValues(a);
      return Array.prototype.map.call(a, function (b) { return ("0" + b.toString(16)).slice(-2); }).join("");
    }
    return String(Date.now()) + Math.random().toString(16).slice(2);
  }
  function debounce(fn, ms) {
    var t; return function () { var a = arguments, s = this; clearTimeout(t); t = setTimeout(function () { fn.apply(s, a); }, ms); };
  }
  var TONE_ICON = { ok: "check-circle", bad: "alert-circle", warn: "alert-triangle", info: "info", neutral: "info", brand: "sparkles" };

  // ---------------------------------------------------------------- toasts
  SF.toast = function (tone, title, text, ms, action) {
    var box = $("#toasts");
    if (!box) return;
    tone = tone || "info";
    var t = el("div", "toast tone-" + tone);
    t.setAttribute("role", tone === "bad" ? "alert" : "status");
    t.appendChild(icon(TONE_ICON[tone] || "info"));
    var body = el("div", "toast-body");
    body.appendChild(el("div", "toast-title", title || ""));
    if (text) body.appendChild(el("div", "toast-text", text));
    t.appendChild(body);
    var acts = Array.isArray(action) ? action : (action ? [action] : []);
    if (acts.length) {
      var actBox = el("div", "toast-actions");
      acts.forEach(function (a) {
        if (!a || !a.label) return;
        var act = el("button", "btn btn-sm btn-secondary toast-action", a.label);
        act.type = "button";
        act.addEventListener("click", function () { act.disabled = true; remove(); a.run(); });
        actBox.appendChild(act);
      });
      body.appendChild(actBox);
    }
    var close = el("button", "icon-btn toast-close");
    close.type = "button"; close.setAttribute("aria-label", "Luk");
    close.appendChild(icon("x"));
    t.appendChild(close);
    function remove() { if (!t.parentNode) return; t.classList.add("is-leaving"); setTimeout(function () { t.remove(); }, 240); }
    close.addEventListener("click", remove);
    box.appendChild(t);
    while (box.children.length > 4) box.firstChild.remove();
    var life = ms || (tone === "bad" ? 9000 : 5200);
    var timer = setTimeout(remove, life);
    t.addEventListener("mouseenter", function () { clearTimeout(timer); });
    t.addEventListener("mouseleave", function () { timer = setTimeout(remove, 2500); });
  };

  // ---------------------------------------------------------------- confirm modal
  var confirmDlg = null;
  function buildConfirm() {
    var d = el("dialog", "modal");
    d.id = "sf-confirm";
    d.setAttribute("aria-labelledby", "sf-confirm-title");
    var card = el("div", "modal-card");
    var ic = el("div", "modal-icon");
    var head = el("div", "modal-head");
    var h = el("h2"); h.id = "sf-confirm-title";
    head.appendChild(h);
    var body = el("div", "modal-body");
    var p = el("p");
    body.appendChild(p);
    var typedWrap = el("div", "field");
    var typedLabel = el("label", "field-label");
    typedLabel.setAttribute("for", "sf-confirm-typed");
    var typed = el("input", "input");
    typed.id = "sf-confirm-typed"; typed.autocomplete = "off"; typed.spellcheck = false;
    typedWrap.appendChild(typedLabel); typedWrap.appendChild(typed);
    body.appendChild(typedWrap);
    var actions = el("div", "modal-actions");
    var cancel = el("button", "btn btn-secondary", "Annullér"); cancel.type = "button"; cancel.value = "cancel";
    var ok = el("button", "btn btn-primary"); ok.type = "button";
    actions.appendChild(cancel); actions.appendChild(ok);
    card.appendChild(ic); card.appendChild(head); card.appendChild(body); card.appendChild(actions);
    d.appendChild(card);
    document.body.appendChild(d);
    d.addEventListener("click", function (e) { if (e.target === d) d.close("cancel"); });
    cancel.addEventListener("click", function () { d.close("cancel"); });
    ok.addEventListener("click", function () { d.close("ok"); });
    return { d: d, ic: ic, h: h, p: p, typedWrap: typedWrap, typedLabel: typedLabel, typed: typed, ok: ok };
  }

  /* SF.confirm({title, text, label, tone, typed}) -> Promise<{ok, typed}> */
  SF.confirm = function (opts) {
    if (!confirmDlg) confirmDlg = buildConfirm();
    var c = confirmDlg;
    var tone = opts.tone === "danger" ? "bad" : (opts.tone || "brand");
    c.ic.className = "modal-icon tone-" + (tone === "primary" ? "brand" : tone);
    c.ic.textContent = "";
    c.ic.appendChild(icon(tone === "bad" ? "alert-triangle" : "shield-check"));
    c.h.textContent = opts.title || "Er du sikker?";
    c.p.textContent = opts.text || "";
    c.p.hidden = !opts.text;
    c.ok.className = "btn " + (opts.tone === "danger" ? "btn-danger" : "btn-primary");
    c.ok.textContent = opts.label || "Bekræft";
    c.typed.value = "";
    if (opts.typed) {
      c.typedWrap.hidden = false;
      c.typedLabel.textContent = "Skriv " + opts.typed + " for at bekræfte";
      c.ok.disabled = true;
      c.typed.oninput = function () { c.ok.disabled = c.typed.value.trim() !== opts.typed; };
    } else {
      c.typedWrap.hidden = true;
      c.ok.disabled = false;
    }
    return new Promise(function (resolveP) {
      c.d.addEventListener("close", function onClose() {
        c.d.removeEventListener("close", onClose);
        resolveP({ ok: c.d.returnValue === "ok", typed: c.typed.value.trim() });
      });
      c.d.returnValue = "";
      c.d.showModal();
      setTimeout(function () { (opts.typed ? c.typed : c.ok).focus(); }, 30);
    });
  };

  function confirmSource(form, submitter) {
    if (submitter && submitter.hasAttribute("data-confirm")) return submitter;
    if (form.hasAttribute("data-confirm")) return form;
    return null;
  }

  // ---------------------------------------------------------------- restart overlay
  SF.restart = function () {
    var ov = $("#restart-overlay");
    if (ov) ov.hidden = false;
    var started = Date.now();
    var sawDown = false;
    function poll() {
      fetch("/healthz", { cache: "no-store", credentials: "same-origin" }).then(function (r) {
        if (r.ok && (sawDown || Date.now() - started > 4000)) { location.reload(); return; }
        if (!r.ok) sawDown = true;
        schedule();
      }).catch(function () { sawDown = true; schedule(); });
    }
    function schedule() {
      if (Date.now() - started > 90000) { location.reload(); return; }
      setTimeout(poll, 1500);
    }
    setTimeout(poll, 2500);
  };

  // ---------------------------------------------------------------- ajax forms
  function setLoading(btn, on) {
    if (!btn || !btn.classList || !btn.classList.contains("btn")) return;
    btn.classList.toggle("is-loading", on);
    btn.disabled = on;
  }

  function applyRows(rows) {
    var removed = 0;
    Object.keys(rows || {}).forEach(function (key) {
      var target = null;
      $$("[data-row]").forEach(function (n) { if (n.getAttribute("data-row") === key) target = n; });
      if (!target) return;
      var html = rows[key];
      // 2.5.0: a row re-rendered or removed while a finger is swiping it
      // (another response of the same sender) drops that gesture and its
      // backdrop - the old node is detached, so its touchend never comes.
      swipeRelease(target, html === null || html === "remove");
      if (html === null || html === "remove") {
        removed++;
        target.classList.add("is-removing");
        setTimeout(function () { target.remove(); updateAllBulk(); maybeEmpty(); }, 320);
      } else {
        var tpl = document.createElement("template");
        tpl.innerHTML = html.trim();
        var fresh = tpl.content.firstElementChild;
        if (fresh) { target.replaceWith(fresh); enhance(fresh); }
      }
    });
    return removed;
  }

  function maybeEmpty() {
    $$("[data-list]").forEach(function (list) {
      if (!list.querySelector("[data-row]")) setTimeout(function () { location.reload(); }, 300);
    });
  }

  function handleResult(data, form) {
    if (!data || typeof data !== "object") data = { ok: false, message: "Uventet svar fra serveren." };
    if (data.ok && data.dialog && data.dialog.html) {
      // 2.3: Bloker/Tillad asks "Kun denne adresse" or "Hele domænet" first.
      SF.ruleDialog(data.dialog, form ? form.querySelector("button") : null);
      return;
    }
    if (data.confirm && data.confirm.url) {
      // 2.3 (B16): e.g. the release of a dangerous mail must be confirmed
      // by an administrator. Mails that needed no confirmation are done.
      var cf = data.confirm;
      if (data.rows) applyRows(data.rows);
      var doneN = (Array.isArray(data.results) ? data.results : []).filter(function (r) { return r && r.ok; }).length;
      if (doneN) SF.toast("ok", data.message || "Udført");
      SF.confirm({ title: cf.title, text: cf.text, label: cf.label, tone: cf.tone }).then(function (r) {
        if (r.ok) runUndo(cf);
      });
      return;
    }
    var results = Array.isArray(data.results) ? data.results : [];
    var failed = results.filter(function (r) { return r && r.ok === false; });
    var title = data.message || (data.ok ? "Udført" : "Handlingen mislykkedes");
    var detail = "";
    if (failed.length) {
      detail = failed.slice(0, 3).map(function (r) { return r.text || r.code || "Fejl"; }).join(" · ");
      if (failed.length > 3) detail += " · +" + (failed.length - 3) + " mere";
    }
    var undo = data.ok && data.undo && data.undo.url ? data.undo : null;
    var acts = [];
    if (undo) acts.push({ label: undo.label || "Fortryd", run: function () { runUndo(undo); } });
    (Array.isArray(data.actions) ? data.actions : []).forEach(function (a) {
      if (a && a.url && a.label) acts.push({ label: a.label, run: function () { runUndo(a); } });
    });
    SF.toast(data.ok ? (failed.length ? "warn" : "ok") : "bad", title, detail, acts.length ? 12000 : 0, acts);
    if (data.rows) applyRows(data.rows);
    if (form && data.ok && form.hasAttribute("data-reset")) {
      form.reset();
      $$("[data-rule-preview]", form).forEach(function (i) { i.dispatchEvent(new Event("input")); });
    }
    if (form) form.dispatchEvent(new CustomEvent("sf:result", { detail: data, bubbles: true }));
    if (data.reload) { setTimeout(SF.restart, 400); return; }
    if (data.redirect) { setTimeout(function () { location.href = data.redirect; }, 450); return; }
    if (data.refresh) setTimeout(function () { location.reload(); }, 650);
  }

  /* Fortryd: post the reverse action the server described. */
  function runUndo(u) {
    var f = document.createElement("form");
    f.method = "post";
    f.setAttribute("action", u.url);
    Object.keys(u.fields || {}).forEach(function (k) {
      var v = u.fields[k];
      (Array.isArray(v) ? v : [v]).forEach(function (x) {
        var i = document.createElement("input");
        i.type = "hidden"; i.name = k; i.value = x == null ? "" : String(x);
        f.appendChild(i);
      });
    });
    SF.submit(f, null);
  }

  SF.submit = function (form, submitter) {
    var fd = new FormData(form);
    if (submitter && submitter.name) fd.append(submitter.name, submitter.value || "");
    if (fd.has("nonce")) fd.set("nonce", nonce());
    if (form.hasAttribute("data-sync")) {
      var row = form.closest("[data-row]");
      var sk = row ? row.getAttribute("data-sync-key") : "";
      if (sk) $$("[data-row]").forEach(function (n) { if (n.getAttribute("data-sync-key") === sk) fd.append("sync", n.getAttribute("data-row")); });
    }
    setLoading(submitter, true);
    form.classList.add("is-busy");
    return fetch(form.getAttribute("action") || location.pathname, {
      method: "POST", body: fd, credentials: "same-origin",
      headers: { "Accept": "application/json", "X-CSRF-Token": csrf(), "X-Requested-With": "fetch" }
    }).then(function (res) {
      if (res.status === 401) { location.href = "/login?next=" + encodeURIComponent(location.pathname + location.search); return null; }
      return res.json().catch(function () {
        return { ok: false, message: res.status === 400 ? "Siden er forældet – genindlæs og prøv igen." : "Uventet svar fra serveren (" + res.status + ")." };
      });
    }).then(function (data) {
      if (data) handleResult(data, form);
      return data;
    }).catch(function () {
      SF.toast("bad", "Ingen forbindelse", "Kunne ikke kontakte filteret. Tjek netværket og prøv igen.");
    }).then(function (d) {
      setLoading(submitter, false);
      form.classList.remove("is-busy");
      return d;
    });
  };

  document.addEventListener("submit", function (e) {
    var form = e.target;
    if (!(form instanceof HTMLFormElement)) return;
    var submitter = e.submitter || null;
    var src = confirmSource(form, submitter);
    var ajax = form.hasAttribute("data-ajax");
    if (!src && !ajax) return;
    if (src && form.__sfConfirmed !== submitter) {
      e.preventDefault();
      var typedReq = src.getAttribute("data-confirm-typed") || "";
      SF.confirm({
        title: src.getAttribute("data-confirm"),
        text: src.getAttribute("data-confirm-text"),
        label: src.getAttribute("data-confirm-label"),
        tone: src.getAttribute("data-confirm-tone"),
        typed: typedReq
      }).then(function (r) {
        if (!r.ok) return;
        if (typedReq) {
          var hiddenIn = form.querySelector('input[name="confirm"]');
          if (!hiddenIn) { hiddenIn = el("input"); hiddenIn.type = "hidden"; hiddenIn.name = "confirm"; form.appendChild(hiddenIn); }
          hiddenIn.value = r.typed;
        }
        if (ajax) { SF.submit(form, submitter); return; }
        form.__sfConfirmed = submitter;
        if (form.requestSubmit) form.requestSubmit(submitter || undefined); else form.submit();
        form.__sfConfirmed = undefined;
      });
      return;
    }
    if (ajax) { e.preventDefault(); SF.submit(form, submitter); }
  });

  // ---------------------------------------------------------------- rules dialog (2.3)
  var ruleDlg = null;
  function fillFrom(node, html) {
    var tpl = document.createElement("template");
    tpl.innerHTML = String(html || "").trim();
    node.textContent = "";
    node.appendChild(tpl.content);
    enhance(node);
  }
  function buildRuleDialog() {
    var d = el("dialog", "modal modal-rule");
    d.id = "sf-rule-dialog";
    d.setAttribute("aria-labelledby", "sf-rule-title");
    document.body.appendChild(d);
    d.addEventListener("click", function (e) {
      if (e.target === d) { d.close(); return; }
      var c = e.target.closest ? e.target.closest("[data-rd-cancel]") : null;
      if (c) { e.preventDefault(); d.close(); }
    });
    // A good result (rule saved / switched / mail released) closes it; an
    // error keeps it open so another choice can be made.
    d.addEventListener("sf:result", function (e) { if (e.detail && e.detail.ok && d.open) d.close(); });
    d.addEventListener("close", function () {
      var back = d.__opener;
      d.__opener = null;
      setTimeout(function () { if (!d.open) d.textContent = ""; }, 260);
      if (back && document.body.contains(back) && back.focus) back.focus();
    });
    return d;
  }
  SF.ruleDialog = function (spec, opener) {
    if (!ruleDlg) ruleDlg = buildRuleDialog();
    var d = ruleDlg;
    d.__opener = opener || document.activeElement;
    fillFrom(d, spec.html);
    // The submit stays disabled until a choice is made (nothing is
    // pre-selected when the address is locked; the server re-checks).
    var rform = $("form[data-rule-form]", d), sub = rform ? $(".rd-submit", rform) : null;
    if (rform && sub) {
      var syncChoice = function () { sub.disabled = !$('input[name="scope"]:checked', rform); };
      rform.addEventListener("change", syncChoice);
      syncChoice();
    }
    if (!d.open) d.showModal();
    var first = $('input[name="scope"]:checked', d) || $('input[name="scope"]:not([disabled])', d)
      || $(".rd-submit:not([disabled])", d) || $("[data-rd-cancel]", d);
    setTimeout(function () { if (first) first.focus(); }, 30);
  };

  // ---------------------------------------------------------------- bulk selection
  function bulkBoxes(id) { return $$('input[name="items"][form="' + id + '"]'); }
  function updateBulk(form) {
    var id = form.id;
    var boxes = bulkBoxes(id);
    var n = boxes.filter(function (b) { return b.checked; }).length;
    $$('[data-bulkbar="' + id + '"]').forEach(function (bar) { bar.classList.toggle("is-hidden", n === 0); });
    $$('[data-bulk-count="' + id + '"]').forEach(function (c) { c.textContent = String(n); });
    $$('[data-select-all="' + id + '"]').forEach(function (all) {
      all.checked = n > 0 && n === boxes.length;
      all.indeterminate = n > 0 && n < boxes.length;
    });
    boxes.forEach(function (b) { var row = b.closest("[data-row]"); if (row) row.classList.toggle("is-selected", b.checked); });
  }
  function updateAllBulk() { $$("form[data-bulk]").forEach(updateBulk); }
  function initBulk() {
    $$("form[data-bulk]").forEach(function (form) {
      var last = null;
      document.addEventListener("click", function (e) {
        var t = e.target;
        if (!(t instanceof HTMLInputElement) || t.name !== "items" || t.getAttribute("form") !== form.id) return;
        var boxes = bulkBoxes(form.id);
        if (e.shiftKey && last && last !== t) {
          var a = boxes.indexOf(last), b = boxes.indexOf(t);
          if (a > -1 && b > -1) boxes.slice(Math.min(a, b), Math.max(a, b) + 1).forEach(function (x) { x.checked = t.checked; });
        }
        last = t;
        updateBulk(form);
      });
      $$('[data-select-all="' + form.id + '"]').forEach(function (all) {
        all.addEventListener("change", function () {
          bulkBoxes(form.id).forEach(function (b) { b.checked = all.checked; });
          updateBulk(form);
        });
      });
      form.addEventListener("sf:result", function () { setTimeout(function () { bulkBoxes(form.id).forEach(function (b) { b.checked = false; }); updateBulk(form); }, 340); });
      updateBulk(form);
    });
  }

  // ---------------------------------------------------------------- menus, modals, misc
  function initMenus() {
    document.addEventListener("click", function (e) {
      $$("details[data-menu][open]").forEach(function (d) { if (!d.contains(e.target)) d.removeAttribute("open"); });
    });
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape") $$("details[data-menu][open]").forEach(function (d) { d.removeAttribute("open"); });
      // 2.10: Ctrl/Cmd+K (Fleetdeck) or "/" jumps to the search field in the top bar.
      if ((e.ctrlKey || e.metaKey) && (e.key === "k" || e.key === "K")) {
        var k = $("[data-search-shortcut]");
        if (k && k.offsetParent !== null) { e.preventDefault(); k.focus(); if (k.select) k.select(); return; }
      }
      if (e.key === "/" && !/^(INPUT|TEXTAREA|SELECT)$/.test((document.activeElement || {}).tagName || "")) {
        var s = $("[data-search-shortcut]");
        if (s) { e.preventDefault(); s.focus(); }
      }
    });
    $$("details[data-menu]").forEach(function (d) {
      d.addEventListener("toggle", function () {
        if (d.open) $$("details[data-menu][open]").forEach(function (o) { if (o !== d) o.removeAttribute("open"); });
      });
    });
  }

  // 2.10.x: the search in the top bar (both menu placements, Fleetdeck):
  // typing shows the pages in the user's menu that match; the top row (and a
  // plain Enter) still finds mails. On the phone the search button opens it.
  function initSearch() {
    var form = document.getElementById("fd-search");
    if (!form) return;
    var input = form.querySelector("input[name=q]"), list = form.querySelector(".fd-search-list");
    if (!input || !list) return;
    var root = document.documentElement;
    var mail = list.querySelector(".fd-search-mail"), echo = list.querySelector("[data-search-echo]");
    var pages = $$("a[data-search-words]", list), none = list.querySelector("[data-search-none]");
    var label = list.querySelector("[data-search-pages-label]"), cur = -1;
    function rows() { return [mail].concat(pages.filter(function (a) { return !a.classList.contains("is-hidden"); })); }
    function mark(i) {
      var r = rows();
      cur = Math.max(0, Math.min(i, r.length - 1));
      r.forEach(function (el, n) { el.classList.toggle("is-current", n === cur); el.setAttribute("aria-selected", n === cur ? "true" : "false"); });
      if (r[cur] && r[cur].scrollIntoView) r[cur].scrollIntoView({ block: "nearest" });
    }
    function show(open) { list.hidden = !open; input.setAttribute("aria-expanded", open ? "true" : "false"); }
    function update() {
      var q = input.value.trim().toLowerCase();
      if (!q) { show(false); return; }
      var words = q.split(/\s+/), hits = 0;
      pages.forEach(function (a) {
        var hay = a.getAttribute("data-search-words") || "";
        var ok = words.every(function (w) { return hay.indexOf(w) !== -1; });
        a.classList.toggle("is-hidden", !ok);
        if (ok) hits++;
      });
      if (echo) echo.textContent = "»" + input.value.trim() + "«";
      if (none) none.hidden = hits > 0;
      if (label) label.hidden = hits === 0;
      show(true);
      mark(0);
    }
    function closeSearch() { show(false); root.classList.toggle("is-search-open", false); }
    input.addEventListener("input", update);
    input.addEventListener("focus", function () { if (input.value.trim()) update(); });
    input.addEventListener("keydown", function (e) {
      if (e.key === "Escape") { e.preventDefault(); closeSearch(); input.blur(); return; }
      if (list.hidden) return;
      if (e.key === "ArrowDown") { e.preventDefault(); mark(cur + 1); }
      else if (e.key === "ArrowUp") { e.preventDefault(); mark(cur - 1); }
      else if (e.key === "Enter") {
        var r = rows()[cur];
        if (r && r.tagName === "A") { e.preventDefault(); window.location.href = r.getAttribute("href"); }
      }
    });
    document.addEventListener("click", function (e) {
      if (form.contains(e.target) || (e.target.closest && e.target.closest("[data-search-open]"))) return;
      closeSearch();
    });
    $$("[data-search-open]").forEach(function (b) {
      b.addEventListener("click", function (e) {
        e.preventDefault();
        var open = !root.classList.contains("is-search-open");
        root.classList.toggle("is-search-open", open);
        if (open) { input.focus(); update(); } else closeSearch();
      });
    });
  }

  function enhance(scope) {
    $$("[data-open-modal]", scope).forEach(function (b) {
      b.addEventListener("click", function () { var d = document.getElementById(b.getAttribute("data-open-modal")); if (d && d.showModal) d.showModal(); });
    });
    $$("[data-close-modal]", scope).forEach(function (b) {
      b.addEventListener("click", function () { var d = b.closest("dialog"); if (d) d.close(); });
    });
    $$("dialog.modal", scope).forEach(function (d) {
      d.addEventListener("click", function (e) { if (e.target === d && !d.hasAttribute("data-auto-open")) d.close(); });
    });
    // 2.11: a dialog rendered open (a new API key, shown once) becomes a real
    // modal that cannot be dismissed by accident (Escape / backdrop); its
    // Færdig link loads the page again, so the key is gone from the DOM.
    $$("dialog[data-auto-open]", scope).forEach(function (d) {
      if (d.open) d.close();
      if (d.showModal) d.showModal();
      d.addEventListener("cancel", function (e) { e.preventDefault(); });
    });
    $$("[data-needs-check]", scope).forEach(function (b) {
      var box = document.getElementById(b.getAttribute("data-needs-check"));
      if (!box) return;
      var sync = function () {
        b.classList.toggle("is-disabled", !box.checked);
        if (box.checked) b.removeAttribute("aria-disabled"); else b.setAttribute("aria-disabled", "true");
      };
      box.addEventListener("change", sync);
      sync();
    });
    $$("[data-copy]", scope).forEach(function (b) {
      b.addEventListener("click", function () { copyText(b.getAttribute("data-copy") || ""); });
    });
    $$("[data-href]", scope).forEach(function (row) {
      row.addEventListener("click", function (e) {
        if (e.target.closest("a,button,input,label,select,textarea,form")) return;
        if (window.getSelection && String(window.getSelection())) return;
        location.href = row.getAttribute("data-href");
      });
    });
    $$('input[type="range"][data-range-output]', scope).forEach(function (r) {
      var out = document.getElementById(r.getAttribute("data-range-output"));
      function sync() { if (out) out.textContent = String(r.value).replace(".", ","); r.dispatchEvent(new CustomEvent("sf:range", { bubbles: true })); }
      r.addEventListener("input", sync);
      sync();
    });
  }

  function copyText(text, label) {
    function done() {
      SF.toast("ok", "Kopieret", label ? label + " er kopieret." : (text.length > 60 ? text.slice(0, 57) + "…" : text), 2500);
    }
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(done, fallback);
    } else { fallback(); }
    function fallback() {
      var ta = el("textarea"); ta.value = text; ta.setAttribute("readonly", "");
      ta.className = "sr-only"; document.body.appendChild(ta); ta.select();
      try { document.execCommand("copy"); done(); } catch (e) { SF.toast("warn", "Kunne ikke kopiere", "Markér teksten og kopiér manuelt."); }
      ta.remove();
    }
  }

  function initNavToggle() {
    var buttons = $$("[data-nav-toggle]");
    if (!buttons.length) return;
    function sync() {
      var mini = root.classList.contains("nav-mini");
      var text = mini ? "Fold menuen ud" : "Klap menuen sammen";
      buttons.forEach(function (b) {
        b.setAttribute("aria-expanded", mini ? "false" : "true");
        b.setAttribute("aria-label", text); b.setAttribute("title", text + " (Ctrl+B)");
        var t = b.querySelector(".nav-toggle-text");
        if (t) t.textContent = text;
      });
    }
    function toggle() {
      var mini = root.classList.toggle("nav-mini");
      try { localStorage.setItem(NAV_KEY, mini ? "1" : "0"); } catch (e) { /* private mode */ }
      sync();
    }
    buttons.forEach(function (b) { b.addEventListener("click", toggle); });
    // Ctrl+B / Cmd+B (shared rule): not while typing, and only where the side
    // menu is shown (desktop, menu in the side) - the button is hidden otherwise.
    document.addEventListener("keydown", function (e) {
      if (!(e.ctrlKey || e.metaKey) || e.altKey || e.shiftKey || (e.key !== "b" && e.key !== "B")) return;
      var a = document.activeElement;
      if (a && (/^(INPUT|TEXTAREA|SELECT)$/.test(a.tagName) || a.isContentEditable)) return;
      if (buttons[0].offsetParent === null) return;
      e.preventDefault();
      toggle();
    });
    sync();
  }

  function initTheme() {
    $$("[data-theme-toggle]").forEach(function (b) {
      b.addEventListener("click", function () {
        var cur = root.getAttribute("data-theme") === "light" ? "light" : "dark";
        SF.setTheme(cur === "light" ? "dark" : "light");
      });
    });
    $$("[data-theme-set]").forEach(function (b) {
      b.addEventListener("click", function () { SF.setTheme(b.getAttribute("data-theme-set")); });
    });
    $$("[data-skin-set]").forEach(function (b) {
      b.addEventListener("click", function () { SF.setSkin(b.getAttribute("data-skin-set")); });
    });
    $$("[data-navpos-set]").forEach(function (b) {
      b.addEventListener("click", function () { SF.setNavPos(b.getAttribute("data-navpos-set")); });
    });
    syncLook();
  }

  function initFlashes() {
    var flashes = $$("[data-flash]");
    flashes.forEach(function (f, i) {
      var tone = f.getAttribute("data-flash") || "info";
      var text = (f.textContent || "").trim();
      setTimeout(function () { SF.toast(tone, text); }, 120 + i * 120);
      f.remove();
    });
    $$(".flashes").forEach(function (box) { if (!box.children.length) box.remove(); });
  }

  function initAutosubmit() {
    // 2.3: a switch that saves itself (the "Gem" button is for no-JS only).
    $$("input[data-switch-submit]").forEach(function (sw) {
      sw.addEventListener("change", function () {
        var f = sw.form;
        if (!f) return;
        if (f.hasAttribute("data-ajax")) SF.submit(f, null); else f.submit();
      });
    });
    $$("form[data-autosubmit]").forEach(function (form) {
      $$("select", form).forEach(function (s) { s.addEventListener("change", function () { form.submit(); }); });
      $$('input[type="radio"]', form).forEach(function (s) { s.addEventListener("change", function () { form.submit(); }); });
    });
  }

  function initFragments() {
    $$("[data-fragment]").forEach(function (box) {
      fetch(box.getAttribute("data-fragment"), { credentials: "same-origin", headers: { "Accept": "text/html" } })
        .then(function (r) { if (!r.ok) throw new Error(String(r.status)); return r.text(); })
        .then(function (html) { box.innerHTML = html; box.removeAttribute("aria-busy"); enhance(box); })
        .catch(function () {
          box.textContent = "";
          var p = el("p", "muted", "Kunne ikke hente data lige nu.");
          box.appendChild(p);
        });
    });
  }

  function initReloadAfter() {
    var box = $("[data-reload-after]");
    if (!box) return;
    var secs = Math.max(5, parseInt(box.getAttribute("data-reload-after"), 10) || 15);
    window.setTimeout(function again() {
      var a = document.activeElement;
      if ((a && /^(INPUT|TEXTAREA|SELECT)$/.test(a.tagName)) || $("dialog[open]")) {
        window.setTimeout(again, 5000);
        return;
      }
      window.location.reload();
    }, secs * 1000);
  }

  function initLive() {
    if (!$("[data-live]")) return;
    function tick() {
      if (document.hidden) return;
      fetch("/api/status", { credentials: "same-origin", cache: "no-store", headers: { "Accept": "application/json" } })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (data) {
          if (!data || !data.live) return;
          $$("[data-live]").forEach(function (node) {
            var v = data.live[node.getAttribute("data-live")];
            if (!v) return;
            if (v.tone) {
              node.className = node.className.replace(/\btone-[a-z]+\b/g, "").trim() + " tone-" + v.tone;
            }
            if (node.hasAttribute("data-live-class")) {
              node.classList.toggle("dot-pulse", !!v.pulse);
              if (v.text != null) { node.setAttribute("aria-label", v.text); node.setAttribute("title", v.text); }
            } else if (v.text != null && node.textContent !== v.text) {
              node.textContent = v.text;
            }
          });
        }).catch(function () { /* offline: keep last values */ });
    }
    setInterval(tick, 15000);
    document.addEventListener("visibilitychange", function () { if (!document.hidden) tick(); });
  }

  function initChartTips() {
    var tip = null;
    function hide() { if (tip) { tip.remove(); tip = null; } }
    document.addEventListener("pointerover", function (e) {
      var col = e.target.closest && e.target.closest(".chart-col[data-tip]");
      if (!col) { hide(); return; }
      var rect = col.getBoundingClientRect();
      hide();
      tip = el("div", "chart-tip", col.getAttribute("data-tip"));
      document.body.appendChild(tip);
      var x = Math.min(Math.max(rect.left + rect.width / 2, 90), window.innerWidth - 90);
      tip.style.left = x + "px";
      tip.style.top = rect.top + "px";
    });
    window.addEventListener("scroll", hide, { passive: true });
  }

  function initRulePreview() {
    $$("input[data-rule-preview]").forEach(function (input) {
      var target = document.getElementById(input.getAttribute("data-rule-preview"));
      var choices = document.getElementById(input.getAttribute("data-rule-choices") || "");
      var existing = document.getElementById(input.getAttribute("data-rule-existing") || "");
      var form = input.form;
      if (!target) return;
      var initialChoices = choices ? choices.innerHTML : "";
      var seq = 0, wantFull = false;
      function checked(name) {
        var r = form ? form.querySelector('input[name="' + name + '"]:checked') : null;
        return r ? r.value : "";
      }
      function syncSubmit() {
        if (!choices || !form) return;
        var fs = $(".rd-choices", choices);
        // Nothing can be chosen, or nothing is chosen yet: no submit.
        var none = !!(fs && !fs.querySelector('input[name="scope"]:checked'));
        $$('.form-actions button[type="submit"]', form).forEach(function (b) {
          b.disabled = !!(fs && fs.hasAttribute("data-blocked")) || none;
        });
      }
      var fire = debounce(function () {
        var full = wantFull; wantFull = false;
        var q = input.value.trim();
        var acct = form && form.elements.account ? form.elements.account.value : "";
        if (!q) {
          render({ tone: "", text: target.getAttribute("data-empty") || "" });
          if (choices) fillFrom(choices, initialChoices);
          if (existing) existing.textContent = "";
          syncSubmit();
          return;
        }
        var url = "/rules/preview?pattern=" + encodeURIComponent(q) + "&account=" + encodeURIComponent(acct);
        if (choices) {
          url += "&form=1&kind=" + encodeURIComponent(checked("kind") || "allow")
            + "&scope=" + encodeURIComponent(checked("scope")) + "&next=" + encodeURIComponent(location.pathname + location.search);
        }
        var my = ++seq;
        fetch(url, { credentials: "same-origin", headers: { "Accept": "application/json" } })
          .then(function (r) { return r.json(); }).then(function (d) {
            if (my !== seq) return;  // a newer request is on its way
            render(d);
            if (full && choices && d.choices_html != null) fillFrom(choices, d.choices_html);
            if (full && existing) fillFrom(existing, d.existing_html || "");
            syncSubmit();
          }).catch(function () { /* keep last */ });
      }, 220);
      // full = also re-render the two choices (typing, Tillad/Bloker,
      // mailbox); a click on a choice only updates the preview line, so
      // keyboard focus stays on the radio.
      function run(full) { if (full !== false) wantFull = true; fire(); }
      function render(d) {
        target.className = "rule-preview" + (d.tone ? " tone-" + d.tone : "");
        target.textContent = "";
        target.appendChild(icon(d.tone === "bad" ? "alert-circle" : d.tone === "ok" ? "check-circle" : d.tone === "warn" ? "alert-triangle" : "info"));
        target.appendChild(el("span", "", d.text || ""));
      }
      input.addEventListener("input", function () { run(true); });
      if (form && form.elements.account) form.elements.account.addEventListener("change", function () { run(true); });
      if (form && choices) {
        form.addEventListener("change", function (e) {
          var t = e.target;
          if (!(t instanceof HTMLInputElement) || t.type !== "radio") return;
          if (t.name === "kind") run(true);
          else if (t.name === "scope") { syncSubmit(); run(false); }
        });
      }
      // A one-click switch of an existing rule: show the new state.
      if (existing) existing.addEventListener("sf:result", function (e) { if (e.detail && e.detail.ok) run(true); });
    });
  }

  // ---------------------------------------------------------------- two-step login + app (2.1)
  // [data-copy-text] + data-copy-label   copy without echoing the text in the toast
  // [data-download-text] + -name         save the text as a file (recovery codes)
  // input[data-otp]                      one-time code field; [data-otp-toggle="<id>"]
  //                                      switches number pad <-> recovery code letters
  // form[data-otp-form]                  login code step: submits by itself at 6 digits
  // [data-install]                       home-screen guide: platform tab, install prompt,
  //                                      "already installed" state
  // [data-offline]                       offline page: reload when the network is back
  function initCodes() {
    $$("[data-copy-text]").forEach(function (b) {
      b.addEventListener("click", function () {
        copyText(b.getAttribute("data-copy-text") || "", b.getAttribute("data-copy-label") || "Teksten");
      });
    });
    $$("[data-download-text]").forEach(function (b) {
      b.addEventListener("click", function () {
        var blob = new Blob([b.getAttribute("data-download-text") || ""], { type: "text/plain;charset=utf-8" });
        var a = el("a");
        a.href = URL.createObjectURL(blob);
        a.download = b.getAttribute("data-download-name") || "spamfilter.txt";
        document.body.appendChild(a); a.click(); a.remove();
        setTimeout(function () { URL.revokeObjectURL(a.href); }, 2000);
      });
    });
  }

  function initOtp() {
    $$("input[data-otp]").forEach(function (input) {
      var form = input.form;
      if (input.hasAttribute("data-otp-recovery")) input.setAttribute("inputmode", "numeric");
      input.addEventListener("input", function () {
        if (input.getAttribute("inputmode") !== "numeric") return;
        var digits = input.value.replace(/\D/g, "").slice(0, 6);
        if (input.value !== digits && /^[\d\s]*$/.test(input.value)) input.value = digits;
        if (form && form.hasAttribute("data-otp-form") && /^\d{6}$/.test(input.value) && !form.__sfSent) {
          form.__sfSent = true;
          if (form.requestSubmit) form.requestSubmit(); else form.submit();
        }
      });
    });
    $$("[data-otp-toggle]").forEach(function (b) {
      var input = document.getElementById(b.getAttribute("data-otp-toggle"));
      if (!input) return;
      var label = b.textContent, alt = b.getAttribute("data-alt-label") || label;
      b.addEventListener("click", function () {
        var numeric = input.getAttribute("inputmode") === "numeric";
        input.setAttribute("inputmode", numeric ? "text" : "numeric");
        input.setAttribute("placeholder", numeric ? "abcde-23456" : "123456");
        b.textContent = numeric ? alt : label;
        input.value = "";
        input.focus();
      });
    });
  }

  // button[data-countdown="N"] (2.3: "Send en ny kode" on login step 2):
  // disabled while the resend cooldown runs, the note next to it counts
  // down ([data-countdown-text]) and disappears when the button is usable.
  function initCountdown() {
    $$("[data-countdown]").forEach(function (b) {
      var left = parseInt(b.getAttribute("data-countdown"), 10) || 0;
      var box = b.closest(".mfa-mail") || document;
      var note = $("[data-countdown-note]", box), text = $("[data-countdown-text]", box);
      if (left <= 0) return;
      b.disabled = true;
      var timer = window.setInterval(function () {
        left -= 1;
        if (left <= 0) {
          window.clearInterval(timer);
          b.disabled = false;
          if (note) note.hidden = true;
          return;
        }
        if (text) text.textContent = left < 90 ? left + " sek" : Math.ceil(left / 60) + " min";
      }, 1000);
    });
  }

  function platform() {
    var ua = navigator.userAgent || "";
    if (/iPhone|iPad|iPod/.test(ua) || (/Macintosh/.test(ua) && navigator.maxTouchPoints > 1)) return "ios";
    if (/Android/.test(ua)) return "android";
    return "";
  }
  function standalone() {
    return (window.matchMedia && window.matchMedia("(display-mode: standalone)").matches) || navigator.standalone === true;
  }

  var installEvent = null;
  window.addEventListener("beforeinstallprompt", function (e) {
    e.preventDefault();
    installEvent = e;
    $$("[data-install-prompt]").forEach(function (b) { b.hidden = false; });
  });
  window.addEventListener("appinstalled", function () {
    installEvent = null;
    $$("[data-install-prompt]").forEach(function (b) { b.hidden = true; });
    SF.toast("ok", "Installeret", "Spamfilteret ligger nu som en app på enheden.");
  });

  function initInstall() {
    $$("[data-install]").forEach(function (box) {
      var tabs = $$("[data-tab]", box);
      function show(name) {
        tabs.forEach(function (t) {
          var on = t.getAttribute("data-tab") === name;
          t.classList.toggle("is-active", on);
          t.setAttribute("aria-selected", on ? "true" : "false");
        });
        $$("[data-tab-panel]", box).forEach(function (p) { p.hidden = p.getAttribute("data-tab-panel") !== name; });
      }
      tabs.forEach(function (t) { t.addEventListener("click", function () { show(t.getAttribute("data-tab")); }); });
      box.classList.add("is-tabbed");
      show(platform() || "ios");
      if (standalone()) {
        var st = $("[data-install-status]", box);
        if (st) st.hidden = false;
      }
    });
    $$("[data-install-prompt]").forEach(function (b) {
      if (installEvent) b.hidden = false;
      b.addEventListener("click", function () {
        if (!installEvent) return;
        installEvent.prompt();
        installEvent.userChoice.then(function () { installEvent = null; b.hidden = true; });
      });
    });
  }

  // Pull to refresh (installed app only: a browser tab has its own). Starts
  // only when the page is scrolled to the very top and the finger is not on
  // a dialog, a form field or a horizontal scroller; pull ~70 px and let go.
  function initPullToRefresh() {
    if (!standalone() || !("ontouchstart" in window)) return;
    var THRESHOLD = 70, MAX = 120;
    var ind = el("div", "ptr");
    ind.setAttribute("aria-hidden", "true");
    ind.appendChild(icon("refresh"));
    document.body.appendChild(ind);
    var startY = null, startX = 0, dist = 0, busy = false;
    var calm = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    function blocked(t) {
      return !!(t && t.closest && t.closest("dialog[open], .modal, [data-no-ptr], input, textarea, select, " +
        "[contenteditable], .table-wrap, .chart, .chart-svg, .tabs"));
    }
    function place(d, animate) {
      ind.classList.toggle("is-dragging", !animate);
      ind.style.setProperty("--ptr-y", d + "px");
      ind.style.setProperty("--ptr-rot", calm ? "0deg" : (d * 3) + "deg");
      ind.style.setProperty("--ptr-o", Math.min(1, d / THRESHOLD));
      ind.classList.toggle("is-armed", d >= THRESHOLD);
    }
    function reset() { startY = null; dist = 0; place(0, true); }
    document.addEventListener("touchstart", function (e) {
      if (busy || e.touches.length !== 1 || window.scrollY > 0 || blocked(e.target)) { startY = null; return; }
      startY = e.touches[0].clientY; startX = e.touches[0].clientX; dist = 0;
    }, { passive: true });
    document.addEventListener("touchmove", function (e) {
      if (startY === null || busy) return;
      // 2.5.0: a mail-row swipe owns the gesture once it went sideways; while
      // it is still deciding (first ~10 px) the indicator waits.
      if (swipePhase === "x") { if (dist) reset(); else startY = null; return; }
      if (swipePhase === "pending") return;
      var dy = e.touches[0].clientY - startY, dx = Math.abs(e.touches[0].clientX - startX);
      if (dy <= 0 || window.scrollY > 0 || dx > dy) { if (dist) reset(); else startY = null; return; }
      dist = Math.min(MAX, dy * 0.5);
      place(dist, false);
    }, { passive: true });
    function end() {
      if (startY === null || busy) return;
      if (dist >= THRESHOLD && swipePhase !== "x") {
        busy = true;
        place(THRESHOLD, true);
        ind.classList.add("is-loading");
        setTimeout(function () { location.reload(); }, 150);
      } else {
        reset();
      }
      startY = null;
    }
    document.addEventListener("touchend", end, { passive: true });
    document.addEventListener("touchcancel", reset, { passive: true });
  }

  // ---------------------------------------------------------------- swipe on mail rows (2.5.0)
  // Fanget spam, Tjek disse and Beskeder on a touch screen (browser and the
  // installed app): stroke a row to the right for Frigiv, to the left for
  // Det er spam. A shortcut for the row's buttons, which stay:
  //   * permissions come from the server only: a direction exists when the
  //     row has data-swipe-right / data-swipe-left, and it posts the row's
  //     form[data-swipe-form] with SF.submit (same URL, fields and CSRF as
  //     the button; Fortryd, threat confirmation and errors as for a click);
  //   * every listener is passive: vertical scrolling is never blocked. The
  //     direction is decided after LOCK px; only a sideways start becomes a
  //     swipe (rows have touch-action: pan-y), and pull to refresh stands
  //     down while a row is being swiped (swipePhase);
  //   * commit past COMMIT of the row width or with a fast fling, otherwise
  //     the row snaps back. Position comes from a custom property set via
  //     CSSOM (style.setProperty), never an inline style attribute.
  var swipePhase = "idle";            // idle | pending | x | y (read by pull to refresh)
  var swipeDrop = null;               // set by initSwipe: (row, removing) -> void
  function swipeRelease(row, removing) { if (swipeDrop) swipeDrop(row, removing); }
  var SWIPE_HINT_KEY = "sf-swipe-hint";
  function reducedMotion() {
    return !!(window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches);
  }
  function isTouch() {
    return ("ontouchstart" in window) || (navigator.maxTouchPoints || 0) > 0;
  }
  function swipeHintDone() {
    try { localStorage.setItem(SWIPE_HINT_KEY, "1"); } catch (e) { /* private mode */ }
    $$(".swipe-hint").forEach(function (n) { n.remove(); });
  }

  function initSwipe() {
    if (!isTouch() || !$("[data-swipe-right], [data-swipe-left]")) return;
    var LOCK = 10;            // px before the direction is decided
    var COMMIT = 0.4;         // share of the row width that commits
    var FLING_V = 0.6;        // px/ms: a fast flick commits early ...
    var FLING_MIN = 48;       // ... once it moved at least this far
    var EDGE = 20;            // px at the screen edges: the browser's back/forward swipe
    var g = null;             // the gesture in progress
    var noClickUntil = 0;

    function swipeRow(t) {
      if (!t || !t.closest || $("dialog[open]")) return null;
      if (t.closest("input, select, textarea, label, [contenteditable], .mail-check, [data-no-swipe]")) return null;
      var row = t.closest("[data-swipe-right], [data-swipe-left]");
      return row && !row.__sfSwipeBusy ? row : null;
    }
    function backdrop(row) {
      var list = row.parentNode;
      list.classList.add("has-swipe");                     // position: relative (offsetParent)
      var bg = el("li", "swipe-bg");
      bg.setAttribute("aria-hidden", "true");
      // The icon sits next to the row's moving edge (it follows the finger
      // until the whole label fits); the text appears only once it fits,
      // never as a cut-off fragment (2.5.0).
      var right = el("span", "swipe-act swipe-act-right");
      right.appendChild(el("span", "swipe-act-text", row.getAttribute("data-swipe-right") || ""));
      right.appendChild(icon("undo"));
      var left = el("span", "swipe-act swipe-act-left");
      left.appendChild(icon("shield-alert"));
      left.appendChild(el("span", "swipe-act-text", row.getAttribute("data-swipe-left") || ""));
      bg.appendChild(right); bg.appendChild(left);
      bg.style.setProperty("--sw-top", row.offsetTop + "px");
      bg.style.setProperty("--sw-h", row.offsetHeight + "px");
      list.insertBefore(bg, row);
      bg.__sfActW = { right: right.offsetWidth, left: left.offsetWidth };
      row.__sfSwipeBg = bg;
      return bg;
    }
    function place(row, x) {
      row.style.setProperty("--sw-x", Math.round(x) + "px");
      var bg = row.__sfSwipeBg;
      if (!bg) return;
      var shown = Math.abs(Math.round(x));               // revealed width behind the row
      var w = bg.__sfActW && bg.__sfActW[x > 0 ? "right" : "left"];
      bg.style.setProperty("--sw-reveal", shown + "px");
      bg.classList.toggle("is-full", !!w && shown >= w + 36);
    }
    function cleanup(row, bg) {
      row.classList.remove("is-swiping", "is-dragging", "is-armed");
      row.style.removeProperty("--sw-x");
      row.style.removeProperty("--sw-row-h");
      row.__sfSwipeBusy = false;
      row.__sfSwipeBg = null;
      if (bg && bg.parentNode) bg.remove();
    }
    // applyRows is about to replace/remove `row`. A gesture still under the
    // finger is dropped (the server changed the row: nothing is posted);
    // a replaced row's backdrop goes with it. A committed row that is being
    // removed keeps its backdrop for the collapse (commit() cleans up).
    swipeDrop = function (row, removing) {
      if (g && g.row === row) {
        if (g.bg && g.bg.parentNode) g.bg.remove();
        row.__sfSwipeBg = null;
        g = null; swipePhase = "idle";
        return;
      }
      if (!removing && row.__sfSwipeBg) {
        if (row.__sfSwipeBg.parentNode) row.__sfSwipeBg.remove();
        row.__sfSwipeBg = null;
      }
    };
    function snapBack(s) {
      var row = s.row, bg = s.bg;
      row.__sfSwipeBusy = true;
      row.classList.remove("is-dragging", "is-armed");
      if (bg) bg.classList.remove("is-armed", "is-busy", "is-dragging");
      place(row, 0);
      setTimeout(function () { cleanup(row, bg); }, reducedMotion() ? 0 : 280);
    }
    // Resistance: 1:1 up to the commit point, then a rubber band; a
    // direction without an action only gives a small nudge.
    function resist(dx, allowed, width) {
      var a = Math.abs(dx), sgn = dx < 0 ? -1 : 1;
      if (!allowed) return sgn * Math.min(28, a * 0.2);
      var t = width * COMMIT;
      return sgn * Math.min(width, a <= t ? a : t + (a - t) * 0.45);
    }
    function setArmed(s, on) {
      if (s.armed === on) return;
      s.armed = on;
      s.row.classList.toggle("is-armed", on);
      s.bg.classList.toggle("is-armed", on);
      if (on && navigator.vibrate) { try { navigator.vibrate(8); } catch (e) { /* not allowed */ } }
    }

    function commit(s, dir) {
      var row = s.row, bg = s.bg;
      var form = $('form[data-swipe-form="' + dir + '"]', row);
      if (!form) { snapBack(s); return; }
      var key = row.getAttribute("data-row");
      row.__sfSwipeBusy = true;
      row.classList.remove("is-dragging");
      bg.classList.remove("is-dragging");
      bg.classList.add("is-busy");
      place(row, (dir === "right" ? 1 : -1) * s.width);   // slides out while the server works
      swipeHintDone();                                     // they know how it works now
      SF.submit(form, null).then(function (data) {
        var rows = (data && data.rows) || {};
        if (!row.isConnected) {
          // Re-rendered with its new state (e.g. Flyt til spam in Beskeder).
          if (bg.parentNode) bg.remove();
          $$("[data-row]").forEach(function (n) { if (n.getAttribute("data-row") === key) n.classList.add("is-swiped-back"); });
          return;
        }
        if (data && data.ok && key && Object.prototype.hasOwnProperty.call(rows, key) && rows[key] === null) {
          // Gone from this list: collapse the gap (applyRows removes the node).
          row.style.setProperty("--sw-row-h", row.offsetHeight + "px");
          void row.offsetHeight;
          row.classList.add("is-collapsing");
          bg.classList.add("is-collapsing");
          setTimeout(function () { if (bg.parentNode) bg.remove(); }, reducedMotion() ? 0 : 320);
          return;
        }
        // Error, nothing done, or the administrator must confirm a
        // dangerous mail first (SF.confirm is open): back in place.
        snapBack(s);
      });
    }

    document.addEventListener("touchstart", function (e) {
      if (g && swipePhase === "x") snapBack(g);
      g = null; swipePhase = "idle";
      if (e.touches.length !== 1) return;
      var row = swipeRow(e.target);
      if (!row) return;
      var p = e.touches[0];
      if (p.clientX < EDGE || p.clientX > window.innerWidth - EDGE) return;
      g = { row: row, bg: null, x0: p.clientX, y0: p.clientY, dx: 0, lastX: p.clientX, lastT: Date.now(), v: 0,
            width: Math.max(1, row.getBoundingClientRect().width), armed: false };
      swipePhase = "pending";
    }, { passive: true, capture: true });

    document.addEventListener("touchmove", function (e) {
      if (!g || e.touches.length !== 1) return;
      var p = e.touches[0];
      var dx = p.clientX - g.x0, dy = p.clientY - g.y0;
      if (swipePhase === "pending") {
        if (Math.abs(dx) < LOCK && Math.abs(dy) < LOCK) return;
        if (Math.abs(dy) >= Math.abs(dx)) { swipePhase = "y"; g = null; return; }   // scrolling: hands off
        swipePhase = "x";
        g.x0 += dx < 0 ? -LOCK : LOCK;                     // no jump at the lock point
        g.bg = backdrop(g.row);
        g.row.classList.add("is-swiping", "is-dragging");
        g.bg.classList.add("is-dragging");
        dx = p.clientX - g.x0;
      }
      if (swipePhase !== "x") return;
      var now = Date.now(), dt = now - g.lastT;
      if (dt > 0) { g.v = 0.6 * ((p.clientX - g.lastX) / dt) + 0.4 * g.v; g.lastX = p.clientX; g.lastT = now; }
      g.dx = dx;
      var dir = dx > 0 ? "right" : "left";
      var allowed = g.row.hasAttribute("data-swipe-" + dir);
      g.bg.classList.toggle("go-right", dx > 0 && allowed);
      g.bg.classList.toggle("go-left", dx < 0 && allowed);
      place(g.row, resist(dx, allowed, g.width));
      setArmed(g, allowed && Math.abs(dx) >= g.width * COMMIT);
    }, { passive: true, capture: true });

    function end() {
      var s = g;
      g = null;
      if (!s || swipePhase !== "x") { swipePhase = "idle"; return; }
      noClickUntil = Date.now() + 450;                     // the lifted finger is not a tap
      var dir = s.dx > 0 ? "right" : "left";
      var allowed = s.row.hasAttribute("data-swipe-" + dir);
      var far = Math.abs(s.dx) >= s.width * COMMIT;
      var fling = Math.abs(s.v) >= FLING_V && Math.abs(s.dx) >= FLING_MIN && (s.v > 0) === (s.dx > 0)
        && Date.now() - s.lastT < 120;
      if (allowed && (far || fling)) commit(s, dir); else snapBack(s);
      setTimeout(function () { if (!g) swipePhase = "idle"; }, 0);
    }
    document.addEventListener("touchend", end, { passive: true, capture: true });
    document.addEventListener("touchcancel", function () {
      var s = g;
      g = null;
      if (s && swipePhase === "x") snapBack(s);
      swipePhase = "idle";
    }, { passive: true, capture: true });
    // A swipe that ended on a link or button must not open/press it.
    document.addEventListener("click", function (e) {
      if (Date.now() < noClickUntil) { e.preventDefault(); e.stopPropagation(); }
    }, true);

    initSwipeHint();
  }

  // One-time tip above the first list with swipeable rows (dismissable;
  // remembered in localStorage, also after the first real swipe).
  function initSwipeHint() {
    try { if (localStorage.getItem(SWIPE_HINT_KEY)) return; } catch (e) { return; }
    var first = $("[data-swipe-right], [data-swipe-left]");
    var list = first && first.closest("[data-list]");
    if (!list || !list.parentNode) return;
    var box = el("div", "swipe-hint");
    box.setAttribute("role", "note");
    box.appendChild(icon("smartphone"));
    box.appendChild(el("span", "swipe-hint-text", "Tip: stryg en mail til højre for Frigiv eller til venstre for Det er spam"));
    var close = el("button", "icon-btn swipe-hint-close");
    close.type = "button";
    close.setAttribute("aria-label", "Skjul tip");
    close.appendChild(icon("x"));
    close.addEventListener("click", swipeHintDone);
    box.appendChild(close);
    list.parentNode.insertBefore(box, list);
  }

  // ---------------------------------------------------------------- push notifications (2.5.0)
  // Web Push needs a secure context (https://spamfilter.example.org), a
  // service worker and the Push API; on iPhone only the app on the home
  // screen has it (iOS 16.4+). Permission is asked ONLY from the button
  // (a user gesture), never on page load.
  function b64uToBytes(s) {
    var pad = "=".repeat((4 - s.length % 4) % 4);
    var raw = atob((s + pad).replace(/-/g, "+").replace(/_/g, "/"));
    var out = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
    return out;
  }
  function bytesToB64u(buf) {
    var b = new Uint8Array(buf || []), s = "";
    for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function sameBytes(a, b) {
    a = new Uint8Array(a || []); b = new Uint8Array(b || []);
    if (a.length !== b.length) return false;
    for (var i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
    return true;
  }
  function endpointHash(endpoint) {
    var data = new TextEncoder().encode(endpoint);
    return crypto.subtle.digest("SHA-256", data).then(function (d) {
      return Array.prototype.map.call(new Uint8Array(d), function (x) { return ("0" + x.toString(16)).slice(-2); }).join("").slice(0, 16);
    });
  }
  function pushSupport() {
    if (!window.isSecureContext) return "insecure";
    var hasPush = "serviceWorker" in navigator && "PushManager" in window && "Notification" in window;
    if (!hasPush) return (platform() === "ios" && !standalone()) ? "ios" : "unsupported";
    if (Notification.permission === "denied") return "denied";
    return "";
  }
  function postForm(url, fields) {
    var fd = new FormData();
    Object.keys(fields).forEach(function (k) { fd.append(k, fields[k]); });
    return fetch(url, {
      method: "POST", body: fd, credentials: "same-origin",
      headers: { "Accept": "application/json", "X-CSRF-Token": csrf(), "X-Requested-With": "fetch" }
    }).then(function (r) {
      return r.json().catch(function () { return { ok: false, message: "Uventet svar fra serveren (" + r.status + ")." }; });
    });
  }
  function initPush() {
    var box = $("[data-push]");
    if (!box) return;
    var checking = $("[data-push-checking]", box);
    function show(state) {
      if (checking) checking.hidden = true;
      $$("[data-push-why]", box).forEach(function (n) { n.hidden = n.getAttribute("data-push-why") !== state; });
      var off = $("[data-push-off]", box), on = $("[data-push-on]", box);
      if (off) off.hidden = state !== "off";
      if (on) on.hidden = state !== "on";
    }
    var why = pushSupport();
    if (why) { show(why); return; }
    var current = null;
    function registration() {
      return navigator.serviceWorker.register("/sw.js", { scope: "/" }).then(function () { return navigator.serviceWorker.ready; });
    }
    function markThisDevice(sub) {
      current = sub;
      if (!sub) { show("off"); return; }
      endpointHash(sub.endpoint).then(function (hash) {
        var mine = null;
        $$("[data-push-hash]", box).forEach(function (row) { if (row.getAttribute("data-push-hash") === hash) mine = row; });
        if (!mine) { show("off"); return; }   // the server forgot it (Fjern, sfctl push-reset): subscribe again
        var chip = $("[data-push-this]", mine);
        if (chip) chip.hidden = false;
        if (mine.parentNode && mine.parentNode.firstElementChild !== mine) mine.parentNode.insertBefore(mine, mine.parentNode.firstElementChild);
        $$("[data-push-endpoint]", box).forEach(function (i) { i.value = sub.endpoint; });
        show("on");
      }).catch(function () { show("off"); });
    }
    navigator.serviceWorker.getRegistration("/").then(function (reg) {
      return reg ? reg.pushManager.getSubscription() : null;
    }).then(markThisDevice).catch(function () { show("off"); });

    $$("[data-push-enable]", box).forEach(function (btn) {
      btn.addEventListener("click", function () {
        // requestPermission() first and synchronously in the tap: iOS
        // only shows the question for a direct user gesture.
        var asked;
        try { asked = Notification.requestPermission(); } catch (e) { asked = null; }
        if (!asked || typeof asked.then !== "function") asked = new Promise(function (res) { Notification.requestPermission(res); });
        setLoading(btn, true);
        var keyBytes = null;
        asked.then(function (perm) {
          if (perm !== "granted") { show(perm === "denied" ? "denied" : "off"); throw null; }
          return fetch(box.getAttribute("data-push-key-url") || "/me/push/key", { credentials: "same-origin", headers: { "Accept": "application/json" } });
        }).then(function (r) { return r.json(); }).then(function (data) {
          if (!data || !data.ok || !data.key) throw new Error((data && data.message) || "Ingen nøgle");
          keyBytes = b64uToBytes(data.key);
          return registration();
        }).then(function (reg) {
          return reg.pushManager.getSubscription().then(function (old) {
            // After sfctl push-reset the server key changed: drop the old subscription first.
            if (old && old.options && old.options.applicationServerKey && !sameBytes(old.options.applicationServerKey, keyBytes)) {
              return old.unsubscribe().then(function () { return null; });
            }
            return old;
          }).then(function (old) {
            return old || reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: keyBytes });
          });
        }).then(function (sub) {
          var j = sub.toJSON ? sub.toJSON() : {};
          var keys = j.keys || {};
          return postForm("/me/push/subscribe", {
            endpoint: sub.endpoint,
            p256dh: keys.p256dh || bytesToB64u(sub.getKey && sub.getKey("p256dh")),
            auth: keys.auth || bytesToB64u(sub.getKey && sub.getKey("auth")),
            app: standalone() ? "1" : "0"
          });
        }).then(function (data) {
          if (data && data.ok) {
            SF.toast("ok", "Beskeder er slået til", data.message || "");
            setTimeout(function () { location.reload(); }, 700);
          } else {
            SF.toast("bad", "Beskeder blev ikke slået til", (data && data.message) || "Prøv igen.");
          }
        }).catch(function (err) {
          if (err) SF.toast("bad", "Beskeder blev ikke slået til", "Telefonen kunne ikke tilmelde sig. Prøv igen om lidt.");
        }).then(function () { setLoading(btn, false); });
      });
    });

    $$("[data-push-disable]", box).forEach(function (btn) {
      btn.addEventListener("click", function () {
        SF.confirm({ title: "Slå beskeder fra?", text: "Denne enhed får ikke flere beskeder fra spamfilteret.", label: "Slå fra", tone: "danger" }).then(function (r) {
          if (!r.ok) return;
          setLoading(btn, true);
          var endpoint = current ? current.endpoint : "";
          var done = current ? current.unsubscribe().catch(function () { return false; }) : Promise.resolve(false);
          done.then(function () {
            return endpoint ? postForm("/me/push/unsubscribe", { endpoint: endpoint }) : { ok: true };
          }).then(function (data) {
            SF.toast(data && data.ok ? "ok" : "bad", (data && data.message) || "Beskeder er slået fra.");
            setTimeout(function () { location.reload(); }, 700);
          }).catch(function () {
            SF.toast("bad", "Ingen forbindelse", "Prøv igen.");
          }).then(function () { setLoading(btn, false); });
        });
      });
    });
  }

  function initPwa() {
    // Service workers need a secure context (https, or localhost); on the
    // plain-http LAN address this simply does nothing.
    if ("serviceWorker" in navigator && window.isSecureContext) {
      navigator.serviceWorker.register("/sw.js", { scope: "/" }).catch(function () { /* optional */ });
    }
    if (document.body && document.body.hasAttribute("data-offline")) {
      window.addEventListener("online", function () { location.reload(); });
      $$("[data-offline-retry]").forEach(function (b) {
        b.addEventListener("click", function (e) { e.preventDefault(); location.reload(); });
      });
    }
    if (standalone()) root.classList.add("is-standalone");
  }

  document.addEventListener("DOMContentLoaded", function () {
    initPwa();
    initPush();
    initPullToRefresh();
    initSwipe();
    initCodes();
    initOtp();
    initCountdown();
    initInstall();
    initTheme();
    initNavToggle();
    initMenus();
    initSearch();
    initFlashes();
    initBulk();
    initAutosubmit();
    initFragments();
    initReloadAfter();
    initLive();
    initChartTips();
    initRulePreview();
    enhance(document);
  });
})();
