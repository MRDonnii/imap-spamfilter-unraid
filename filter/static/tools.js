/* spamfilter 2.1 - Find en mail / Fortryd flytninger helpers.
   Loaded per page (<script src defer>), CSP-clean (no inline code).

     form[data-busy]            spinner on the submit button while the
                                (read-only) mailbox search runs
     [data-undo-poll="/url"]    live progress of an undo job
*/
(function () {
  "use strict";

  function $(sel, root) { return (root || document).querySelector(sel); }
  function $$(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }

  // Busy state for slow, non-AJAX forms (the live mailbox search).
  $$("form[data-busy]").forEach(function (form) {
    form.addEventListener("submit", function () {
      var btn = $("button[type=submit], button:not([type])", form);
      if (btn) {
        btn.classList.add("is-loading");
        btn.setAttribute("aria-busy", "true");
      }
    });
  });

  // Undo job progress.
  var box = $("[data-undo-poll]");
  if (!box) return;
  var url = box.getAttribute("data-undo-poll");
  var active = box.getAttribute("data-undo-active") === "1";
  var tones = ["ok", "warn", "bad", "info", "neutral", "brand"];

  function setTone(node, tone) {
    tones.forEach(function (t) { node.classList.remove("tone-" + t); });
    node.classList.add("tone-" + tone);
  }

  function render(job) {
    var pct = Math.max(0, Math.min(100, parseInt(job.percent, 10) || 0));
    var status = $("[data-undo-status]", box);
    if (status) { status.textContent = job.status_label || ""; setTone(status, job.tone || "neutral"); }
    var p = $("[data-undo-pct]", box);
    if (p) p.textContent = pct + " %";
    var bar = $("[data-undo-bar]", box);
    if (bar) { bar.setAttribute("aria-valuenow", String(pct)); setTone(bar, job.status === "done" ? "ok" : "brand"); }
    var fill = $("[data-undo-fill]", box);
    if (fill) fill.className = "progress-fill p-" + pct;
    var text = $("[data-undo-text]", box);
    if (text && job.text) text.textContent = job.text;
    $$("[data-undo-n]", box).forEach(function (n) {
      var v = job[n.getAttribute("data-undo-n")];
      if (v !== undefined && v !== null) n.textContent = String(v);
    });
  }

  function tick() {
    fetch(url, { credentials: "same-origin", cache: "no-store", headers: { "Accept": "application/json" } })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (data) {
        if (!data || !data.job) return;
        render(data.job);
        if (data.job.active) {
          setTimeout(tick, 2000);
        } else if (active) {
          active = false;
          // Finished while we watched: reload once so the stop button goes away.
          setTimeout(function () { window.location.reload(); }, 900);
        }
      })
      .catch(function () { setTimeout(tick, 5000); });
  }

  if (active) setTimeout(tick, 1500);
})();
