/* spamfilter 2.0 — administration pages (Konti, Træning, Drift,
   Indstillinger). Loaded with `defer` after app.js; uses window.SF.
   Everything here is progressive enhancement: every form also works
   without JS (the server re-validates and re-tests everything).

   Hooks:
     a[data-open-modal]                 link fallback for no-JS; JS opens the dialog instead
     input[data-thr-preview]            threshold slider: live "would have caught N of M"
     input[data-whatif]                 calibration what-if slider ([data-whatif-row] JSON)
     form[data-conn-test]               connection test result panel + test token; buttons
                                        [data-needs-test] stay disabled until a test passed
     input[data-suggest]                wizard: provider autofill from /accounts/suggest
     select[data-new-folder-select]     shows [data-new-folder="<select id>"] for "Opret ny mappe…"
     select[data-folders]               folder list narrowed to [data-folder-source] account
     [data-jobs-live="/url"]            job rows refreshed while a job is active
     [data-theme-set]                   pressed state for the theme buttons
     input[data-match="<id>"]           password confirmation must match
     [data-pw-group]                    "Generér stærk kode": [data-pw-generate] fills input[data-pw] +
                                        its repeat, shows it in [data-pw-out]/[data-pw-value], [data-pw-copy]
     [data-access-form]                 Brugere: role radios hide [data-role-user] for admins; live
                                        [data-access-summary] from input[data-acct-name] / input[data-perm-word];
                                        [data-self-demote] checkbox becomes required when you demote yourself
     reply.location                     history.replaceState before the restart overlay reloads
     input[data-check-all]              (2.2 Reparér Bayes) toggles every input[data-check-item] in the same
                                        form; [data-check-count] shows how many are chosen
     form[data-smtp-form]               (2.3 Mailserver) [data-smtp-fill] provider chips fill host/port/
                                        security; the "Login" radios show only the matching
                                        [data-smtp-auth-group]; choosing a mailbox ([data-smtp-account])
                                        suggests its provider's server when the server field is empty
     input[data-typed-confirm="WORD"]   (2.3 Byg Bayes op på ny) the form's [data-typed-target] button stays
                                        disabled until WORD is typed (the server checks it again)
     [data-rebuild-live="/url"]         (2.3) rebuild status re-fetched every 5 s while it holds
                                        [data-rebuild-active]; a toast when it is done
*/
(function () {
  "use strict";
  function $(sel, ctx) { return (ctx || document).querySelector(sel); }
  function $$(sel, ctx) { return Array.prototype.slice.call((ctx || document).querySelectorAll(sel)); }
  function el(tag, cls, text) { var e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; }
  function fmtInt(n) { return String(Math.round(n)).replace(/\B(?=(\d{3})+(?!\d))/g, "."); }
  function fmtScore(v) { return Number(v).toFixed(1).replace(".", ","); }
  function pct(part, whole) {
    if (!whole) return "–";
    var v = part / whole * 100;
    return (v < 10 ? v.toFixed(1) : v.toFixed(0)).replace(".", ",") + " %";
  }
  function sensitivity(t) { return t <= 6 ? "Streng" : (t >= 9 ? "Lempelig" : "Normal"); }
  function plural(n, one, many) { return fmtInt(n) + " " + (n === 1 ? one : many); }
  function parse(json) { try { return JSON.parse(json); } catch (e) { return null; } }
  function toast(tone, title, text) { if (window.SF && SF.toast) SF.toast(tone, title, text); }

  // ------------------------------------------------------------ modal links
  document.addEventListener("click", function (e) {
    var a = e.target.closest && e.target.closest("a[data-open-modal]");
    if (!a) return;
    var d = document.getElementById(a.getAttribute("data-open-modal"));
    if (d && d.showModal) { e.preventDefault(); if (!d.open) d.showModal(); }
  });

  // ------------------------------------------------------------ threshold preview
  function initThreshold() {
    $$("input[data-thr-preview]").forEach(function (r) {
      var data = parse(r.getAttribute("data-thr-preview"));
      var form = r.closest("form") || document;
      var label = $("[data-thr-label]", form);
      var main = $('[data-tp="main"]', form), fp = $('[data-tp="fp"]', form), miss = $('[data-tp="miss"]', form);
      var out = document.getElementById(r.getAttribute("data-range-output") || "");
      function render() {
        var t = parseFloat(r.value);
        if (out) out.textContent = fmtScore(t);
        if (label) label.textContent = sensitivity(t);
        r.style.setProperty("--fill", ((t - r.min) / (r.max - r.min) * 100) + "%");
        if (!data || !data.m) return;
        var s = data.steps[t.toFixed(1)] || [0, 0, 0];
        if (main) main.textContent = fmtInt(s[0]) + " af de seneste " + fmtInt(data.m) + " beskeder ville være fanget (" + pct(s[0], data.m) + ").";
        if (fp) { fp.hidden = !s[1]; fp.textContent = s[1] ? "Heraf " + plural(s[1], "besked", "beskeder") + ", som du selv har frigivet." : ""; }
        if (miss) { miss.hidden = !s[2]; miss.textContent = s[2] ? plural(s[2], "besked", "beskeder") + ", du selv har kaldt spam, ville slippe igennem." : ""; }
      }
      r.addEventListener("input", render);
      r.addEventListener("sf:range", render);  // app.js mirrors the raw value first
      render();
    });
  }

  // ------------------------------------------------------------ calibration what-if
  function initWhatif() {
    $$("input[data-whatif]").forEach(function (r) {
      var scope = r.closest(".card") || document;
      var label = $("[data-thr-label]", scope);
      var out = document.getElementById(r.getAttribute("data-range-output") || "");
      var rows = $$("[data-whatif-row]", scope).map(function (row) {
        return { row: row, d: parse(row.getAttribute("data-whatif-row")) || {} };
      });
      function render() {
        var t = parseFloat(r.value);
        if (out) out.textContent = fmtScore(t);
        if (label) label.textContent = sensitivity(t);
        r.style.setProperty("--fill", ((t - r.min) / (r.max - r.min) * 100) + "%");
        rows.forEach(function (x) {
          var c = (x.d.caught || {})[t.toFixed(1)] || 0, n = x.d.count || 0;
          var out = $('[data-wi="count"]', x.row);
          if (out) out.textContent = fmtInt(c) + " af " + fmtInt(n) + " (" + pct(c, n) + ")";
          var bar = $(".progress", x.row), fill = $(".progress-fill", x.row);
          var p = n ? Math.max(0, Math.min(100, Math.round(c / n * 100))) : 0;
          if (fill) fill.className = "progress-fill p-" + p;
          if (bar) bar.setAttribute("aria-valuenow", String(p));
        });
      }
      r.addEventListener("input", render);
      r.addEventListener("sf:range", render);
      render();
    });
  }

  // ------------------------------------------------------------ connection test
  function testPanel(box, data) {
    var t = data.test || {};
    box.hidden = false;
    box.textContent = "";
    box.className = "test-result tone-" + (data.ok ? "ok" : "bad");
    var head = el("div", "test-head");
    var title = data.ok ? "Forbindelsen virker" : "Forbindelsen fejlede";
    var msg = (data.message || t.text || "").replace(/\.$/, "");
    head.appendChild(el("b", "", title));
    if (msg && msg !== title) head.appendChild(el("span", "", data.message || t.text));
    box.appendChild(head);
    if (!data.ok) return;
    var facts = el("div", "test-facts");
    function fact(k, v) { var f = el("div", "test-fact"); f.appendChild(el("span", "", k)); f.appendChild(el("b", "", v)); facts.appendChild(f); }
    fact("Flyttemetode", t.move_label || t.move_method || "–");
    fact("IDLE", t.idle ? "Ja" : "Nej");
    fact("Mapper", fmtInt((t.folders || []).length));
    box.appendChild(facts);
    if (t.move_method === "none") box.appendChild(el("p", "test-warn", "Serveren kan ikke flytte beskeder sikkert – brug Markér i stedet for Filtrér."));
  }

  function fillFolders(form, test) {
    var sel = $("select[data-folder-target]", form);
    if (!sel || !test || !test.folders) return;
    var keep = sel.value;
    var existing = {};
    $$("option", sel).forEach(function (o) { existing[o.value] = true; });
    var newOpt = $('option[value="__new__"]', sel);
    test.folders.forEach(function (f) {
      if (existing[f.name] || /^inbox$/i.test(f.name)) return;
      var flags = (f.flags || []).map(function (x) { return String(x).toLowerCase(); });
      if (flags.indexOf("\\sent") > -1 || flags.indexOf("\\drafts") > -1 || flags.indexOf("\\trash") > -1) return;
      var o = el("option", "", f.name + (flags.indexOf("\\junk") > -1 ? " · udbyderens spam-mappe" : ""));
      o.value = f.name;
      sel.insertBefore(o, newOpt);
    });
    sel.value = keep;
  }

  function initConnForms() {
    $$("form[data-conn-test]").forEach(function (form) {
      var saves = $$("[data-needs-test]", form);
      var tested = $('input[name="tested"]', form);
      var box = $("[data-test-result]", form);
      function lock() { saves.forEach(function (b) { b.disabled = true; b.title = "Test forbindelsen først"; }); if (tested) tested.value = ""; }
      lock();
      $$("[data-conn]", form).forEach(function (i) { i.addEventListener("input", function () { lock(); if (box) box.hidden = true; }); });
      form.addEventListener("sf:result", function (e) {
        var data = e.detail || {};
        if (data.location) { try { history.replaceState(null, "", data.location); } catch (err) { /* ignore */ } }
        if (!data.test) return;
        if (box) testPanel(box, data);
        if (data.ok && data.token) {
          if (tested) tested.value = data.token;
          saves.forEach(function (b) { b.disabled = false; b.title = ""; });
          fillFolders(form, data.test);
        } else if (!data.ok) { lock(); }
      });
    });
    // Any other ajax reply that moves us elsewhere after the restart overlay.
    document.addEventListener("sf:result", function (e) {
      var d = e.detail || {};
      if (d.location && !(e.target && e.target.hasAttribute && e.target.hasAttribute("data-conn-test"))) {
        try { history.replaceState(null, "", d.location); } catch (err) { /* ignore */ }
      }
    });
  }

  // ------------------------------------------------------------ wizard autofill
  function initSuggest() {
    $$("input[data-suggest]").forEach(function (input) {
      var form = input.form;
      var host = form.elements.imap_host, port = form.elements.imap_port, user = form.elements.user, name = form.elements.name;
      var info = $("[data-provider]", form);
      var touched = {}, filling = false;
      [host, port, user, name].forEach(function (f) { if (f) f.addEventListener("input", function () { if (!filling) touched[f.name] = true; }); });
      var last = "";
      function run() {
        var v = input.value.trim();
        if (!v || v === last || v.indexOf("@") < 1) return;
        last = v;
        if (user && !touched.user) { filling = true; user.value = v; user.dispatchEvent(new Event("input")); filling = false; }
        fetch("/accounts/suggest?email=" + encodeURIComponent(v), { credentials: "same-origin", headers: { "Accept": "application/json" } })
          .then(function (r) { return r.json(); })
          .then(function (d) {
            if (!d || !d.ok) return;
            if (host && !touched.imap_host) host.value = d.imap_host || "";
            if (port && !touched.imap_port) port.value = d.imap_port || 993;
            if (name && !touched.name) name.value = d.name || "";
            filling = true;  // let the connection form drop any old test token
            [host, port, user].forEach(function (f) { if (f) f.dispatchEvent(new Event("input")); });
            filling = false;
            if (info) {
              info.hidden = false;
              info.className = "wiz-provider tone-" + (d.exists ? "bad" : (d.guess ? "warn" : "ok"));
              info.textContent = d.exists ? "Denne adresse er allerede tilføjet." :
                (d.guess ? "Ukendt udbyder – tjek servernavnet (gættet: " + d.imap_host + ")." :
                  "Kendt udbyder: " + (d.provider || d.imap_host) + " – serveren er udfyldt.");
            }
          }).catch(function () { /* offline: user types the server */ });
      }
      input.addEventListener("change", run);
      input.addEventListener("blur", run);
    });
  }

  // ------------------------------------------------------------ "Opret ny mappe…"
  function initNewFolder() {
    $$("select[data-new-folder-select]").forEach(function (sel) {
      var box = document.querySelector('[data-new-folder="' + sel.id + '"]');
      if (!box) return;
      var input = $("input", box);
      function sync() {
        var on = sel.value === "__new__";
        box.hidden = !on;
        if (input) { input.required = on; if (on) input.focus(); }
      }
      sel.addEventListener("change", sync);
      box.hidden = sel.value !== "__new__";
    });
  }

  // ------------------------------------------------------------ folder list per account
  function initFolderSelects() {
    $$("select[data-folder-source]").forEach(function (acct) {
      var target = document.getElementById(acct.getAttribute("data-folder-source"));
      if (!target) return;
      var all = parse(target.getAttribute("data-folders")) || {};
      function rebuild() {
        var opts = all[acct.value] || [];
        var keep = target.value;
        target.textContent = "";
        opts.forEach(function (o) { var op = el("option", "", o[1]); op.value = o[0]; target.appendChild(op); });
        if (opts.some(function (o) { return o[0] === keep; })) target.value = keep;
      }
      acct.addEventListener("change", rebuild);
      rebuild();
    });
  }

  // ------------------------------------------------------------ live job rows
  function initJobs() {
    var box = $("[data-jobs-live]");
    if (!box) return;
    var url = box.getAttribute("data-jobs-live");
    var timer = null;
    function active() { return !!$("[data-job-active]", box); }
    function tick() {
      if (document.hidden) { schedule(); return; }
      fetch(url, { credentials: "same-origin", cache: "no-store", headers: { "Accept": "application/json" } })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (d) {
          if (!d || !d.rows) return;
          var missing = false;
          Object.keys(d.rows).forEach(function (key) {
            var cur = null;
            $$("[data-row]", box).forEach(function (n) { if (n.getAttribute("data-row") === key) cur = n; });
            if (!cur) { missing = true; return; }
            var tpl = document.createElement("template");
            tpl.innerHTML = "<table><tbody>" + d.rows[key] + "</tbody></table>";
            var fresh = tpl.content.querySelector("tr");
            if (fresh && fresh.outerHTML !== cur.outerHTML) cur.replaceWith(fresh);
          });
          if (missing) { location.reload(); return; }
          if (!d.active) {
            var done = $$('[data-row^="job:"]', box).length;
            if (done) toast("ok", "Job færdige", "Alle job i køen er afsluttet.");
          }
        }).catch(function () { /* keep last values */ })
        .then(schedule);
    }
    function schedule() { clearTimeout(timer); if (active()) timer = setTimeout(tick, 3000); }
    box.addEventListener("click", function () { setTimeout(schedule, 400); });
    document.addEventListener("sf:result", function () { setTimeout(function () { if (active()) tick(); }, 300); });
    schedule();
  }

  // ------------------------------------------------------------ typed confirmation (2.3)
  function initTypedConfirm() {
    $$("input[data-typed-confirm]").forEach(function (inp) {
      var form = inp.closest("form");
      if (!form) return;
      var want = inp.getAttribute("data-typed-confirm");
      var btns = $$("[data-typed-target]", form);
      function norm(v) { return String(v || "").replace(/\s+/g, " ").trim().toUpperCase(); }
      function sync() {
        var ok = norm(inp.value) === want;
        btns.forEach(function (b) { b.disabled = !ok; b.setAttribute("aria-disabled", ok ? "false" : "true"); });
      }
      inp.addEventListener("input", sync);
      form.addEventListener("sf:result", function () { setTimeout(sync, 0); });
      sync();
    });
  }

  // ------------------------------------------------------------ live rebuild status (2.3)
  function initRebuildLive() {
    $$("[data-rebuild-live]").forEach(function (box) {
      var url = box.getAttribute("data-rebuild-live");
      var timer = null, wasActive = false;
      function active() { return !!$("[data-rebuild-active]", box); }
      function busy() { return box.getAttribute("aria-busy") === "true"; }
      function tick() {
        if (document.hidden) { schedule(); return; }
        fetch(url, { credentials: "same-origin", cache: "no-store", headers: { "Accept": "application/json" } })
          .then(function (r) { return r.ok ? r.json() : null; })
          .then(function (d) {
            if (!d || typeof d.html !== "string") return;
            box.innerHTML = d.html;
            box.removeAttribute("aria-busy");
            if (wasActive && !d.active) toast("ok", "Bayes er bygget op", "Genopbygningens job er færdige.");
          }).catch(function () { /* keep last values */ })
          .then(schedule);
      }
      function schedule() {
        clearTimeout(timer);
        var a = active();
        if (a) wasActive = true;
        if (a || busy()) timer = setTimeout(tick, a ? 5000 : 1500);
      }
      document.addEventListener("sf:result", function () { setTimeout(tick, 400); });
      schedule();
    });
  }

  // ------------------------------------------------------------ theme buttons
  function initThemeButtons() {
    var btns = $$("[data-theme-set]");
    if (!btns.length) return;
    function mark() {
      var cur = window.SF && SF.getTheme ? SF.getTheme() : "system";
      btns.forEach(function (b) {
        var on = b.getAttribute("data-theme-set") === cur;
        b.setAttribute("aria-pressed", on ? "true" : "false");
        b.classList.toggle("is-active", on);
      });
    }
    btns.forEach(function (b) { b.addEventListener("click", function () { setTimeout(mark, 0); }); });
    $$("[data-theme-toggle]").forEach(function (b) { b.addEventListener("click", function () { setTimeout(mark, 0); }); });
    mark();
  }

  // ------------------------------------------------------------ password confirmation + scope switches
  function initPasswords() {
    $$("input[data-match]").forEach(function (i) {
      var other = document.getElementById(i.getAttribute("data-match"));
      if (!other) return;
      function check() { i.setCustomValidity(i.value && i.value !== other.value ? "Adgangskoderne er ikke ens." : ""); }
      i.addEventListener("input", check);
      other.addEventListener("input", check);
    });
    $$("form").forEach(function (form) {
      var list = $("[data-scope-accounts]", form);
      if (!list) return;
      var radios = $$('input[name="role"]', form);
      function sync() {
        var acc = radios.some(function (r) { return r.checked && r.value === "accounts"; });
        list.hidden = !acc;
      }
      radios.forEach(function (r) { r.addEventListener("change", sync); });
      sync();
    });
  }

  // ------------------------------------------------------------ Brugere
  var PW_ALPHABET = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";  // no 0/O, 1/l/I
  function strongPassword() {
    // 20 symbols from 55 (~115 bits), rejection sampling (no modulo bias), groups of 5.
    var out = "", limit = Math.floor(4294967296 / PW_ALPHABET.length) * PW_ALPHABET.length;
    var buf = new Uint32Array(1);
    while (out.length < 20) {
      crypto.getRandomValues(buf);
      if (buf[0] < limit) out += PW_ALPHABET.charAt(buf[0] % PW_ALPHABET.length);
    }
    return out.replace(/(.{5})(?!$)/g, "$1-");
  }
  function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) return navigator.clipboard.writeText(text);
    return new Promise(function (resolve, reject) {
      // Plain http on the LAN has no async clipboard: classic fallback.
      var ta = el("textarea", "sr-only");
      ta.value = text; ta.setAttribute("readonly", "");
      document.body.appendChild(ta); ta.select();
      var ok = false;
      try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
      ta.remove();
      if (ok) resolve(); else reject(new Error("copy"));
    });
  }
  function initPwGenerators() {
    $$("[data-pw-group]").forEach(function (g) {
      var btn = $("[data-pw-generate]", g), out = $("[data-pw-out]", g), val = $("[data-pw-value]", g);
      var copy = $("[data-pw-copy]", g), pw = $("input[data-pw]", g), pw2 = $("input[data-match]", g);
      if (!btn || !pw || !(window.crypto && crypto.getRandomValues)) { if (btn) btn.hidden = true; return; }
      btn.addEventListener("click", function () {
        var p = strongPassword();
        pw.value = p;
        if (pw2) pw2.value = p;
        [pw, pw2].forEach(function (i) { if (i) i.dispatchEvent(new Event("input", { bubbles: true })); });
        if (val) val.textContent = p;
        if (out) out.hidden = false;
        toast("ok", "Stærk kode lavet", "Kopiér den og giv den til brugeren – den kan ikke ses igen, når du har gemt.");
      });
      if (copy) copy.addEventListener("click", function () {
        copyText(val ? val.textContent : pw.value).then(function () { toast("ok", "Kopieret", "Koden ligger i udklipsholderen."); },
          function () { toast("warn", "Kunne ikke kopiere", "Markér koden og kopiér den selv."); });
      });
      var form = g.closest("form");
      if (form) form.addEventListener("reset", function () { if (out) out.hidden = true; if (val) val.textContent = ""; });
    });
  }
  function daJoin(items) {
    if (items.length <= 1) return items.join("");
    return items.slice(0, -1).join(", ") + " og " + items[items.length - 1];
  }
  function initAccessForms() {
    $$("[data-access-form]").forEach(function (box) {
      var radios = $$('input[name="role"]', box);
      var userPart = $("[data-role-user]", box);
      var sum = $("[data-access-summary]", box);
      var sumText = $("[data-access-summary-text]", box);
      var demote = $("[data-self-demote]", box);
      function isAdmin() { return radios.some(function (r) { return r.checked && r.value === "admin"; }); }
      function render() {
        var admin = isAdmin();
        if (userPart) userPart.hidden = admin;
        if (demote) {
          demote.hidden = admin;
          var cb = $("input", demote);
          if (cb) cb.required = !admin;
        }
        if (!sumText) return;
        if (admin) { sumText.textContent = sum.getAttribute("data-admin-text") || ""; return; }
        var names = $$("input[data-acct-name]", box).filter(function (c) { return c.checked; })
          .map(function (c) { return c.getAttribute("data-acct-label") || c.getAttribute("data-acct-name"); }).sort();
        var words = $$("input[data-perm-word]", box).filter(function (c) { return c.checked; })
          .map(function (c) { return c.getAttribute("data-perm-word"); });
        sumText.textContent = (names.length ? "Kan se " + daJoin(names) : "Kan ikke se nogen postkasser endnu")
          + " · " + (words.length ? "Må " + daJoin(words) : "Må kun se fanget spam");
      }
      box.addEventListener("change", render);
      render();
    });
  }

  // ------------------------------------------------------------ check groups (Reparér Bayes)
  function initCheckGroups() {
    $$("input[data-check-all]").forEach(function (all) {
      var form = all.closest("form");
      if (!form) return;
      function items() { return $$("input[data-check-item]", form); }
      function update() {
        var boxes = items();
        var n = boxes.filter(function (b) { return b.checked; }).length;
        all.checked = n > 0 && n === boxes.length;
        all.indeterminate = n > 0 && n < boxes.length;
        $$("[data-check-count]", form).forEach(function (c) { c.textContent = fmtInt(n); });
        $$('button[type="submit"]', form).forEach(function (b) { b.disabled = n === 0; });
        boxes.forEach(function (b) { var row = b.closest("tr"); if (row) row.classList.toggle("is-selected", b.checked); });
      }
      all.addEventListener("change", function () {
        items().forEach(function (b) { b.checked = all.checked; });
        update();
      });
      form.addEventListener("change", function (e) { if (e.target && e.target.hasAttribute("data-check-item")) update(); });
      update();
    });
  }

  // ------------------------------------------------------------ mail server (2.3)
  function initSmtpForms() {
    $$("form[data-smtp-form]").forEach(function (form) {
      var host = $("[data-smtp-host]", form), port = $("[data-smtp-port]", form);
      function fill(src, force) {
        if (!src) return;
        if (host && (force || !host.value.trim())) host.value = src.getAttribute("data-host") || host.value;
        if (port && (force || !host || host.value === src.getAttribute("data-host"))) {
          port.value = src.getAttribute("data-port") || port.value;
        }
        var sec = src.getAttribute("data-security");
        $$('[data-smtp-security] input[type="radio"]', form).forEach(function (r) {
          if (sec && (force || host.value === src.getAttribute("data-host"))) r.checked = r.value === sec;
        });
      }
      $$("[data-smtp-fill]", form).forEach(function (b) {
        b.addEventListener("click", function () { fill(b, true); if (host) host.focus(); });
      });
      var radios = $$('[data-smtp-auth] input[type="radio"]', form);
      function sync() {
        var mode = "password";
        radios.forEach(function (r) { if (r.checked) mode = r.value; });
        $$("[data-smtp-auth-group]", form).forEach(function (g) {
          g.hidden = g.getAttribute("data-smtp-auth-group") !== mode;
        });
      }
      radios.forEach(function (r) { r.addEventListener("change", sync); });
      sync();
      var acct = $("[data-smtp-account]", form);
      if (acct) acct.addEventListener("change", function () {
        var hint = $('[data-smtp-account-hint="' + acct.value.replace(/["\\]/g, "") + '"]', form);
        fill(hint, false);
      });
    });
  }

  function init() {
    initSmtpForms();
    initCheckGroups();
    initPwGenerators();
    initAccessForms();
    initThreshold();
    initWhatif();
    initConnForms();
    initSuggest();
    initNewFolder();
    initFolderSelects();
    initJobs();
    initTypedConfirm();
    initRebuildLive();
    initThemeButtons();
    initPasswords();
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init); else init();
})();
