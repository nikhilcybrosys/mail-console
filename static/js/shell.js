/* Shell behaviour: toasts, copy, confirm dialog, auto-submit selects, keyboard shortcuts. */
(function () {
  var MC = (window.MC = window.MC || {});
  var ICON = { ok: "i-circle-check", err: "i-circle-alert", info: "i-info" };
  MC.toast = function (msg, tone) {
    var box = document.getElementById("toasts"); if (!box) return;
    tone = tone || "info";
    var el = document.createElement("div"); el.className = "toast is-" + tone; el.setAttribute("role", tone === "err" ? "alert" : "status");
    var ns = "http://www.w3.org/2000/svg", svg = document.createElementNS(ns, "svg"), use = document.createElementNS(ns, "use");
    svg.setAttribute("class", "icon"); svg.setAttribute("aria-hidden", "true");
    use.setAttribute("href", box.getAttribute("data-sprite") + "#" + ICON[tone]); svg.appendChild(use);
    var span = document.createElement("span"); span.textContent = msg;  // textContent: never HTML
    el.appendChild(svg); el.appendChild(span); box.appendChild(el);
    setTimeout(function () { el.remove(); }, tone === "err" ? 8000 : 4000);
  };
  // Server-rendered Django messages become toasts too.
  document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll("[data-flash]").forEach(function (n) { MC.toast(n.textContent.trim(), n.getAttribute("data-flash")); n.remove(); });
  });
  document.addEventListener("htmx:responseError", function () { MC.toast("That request failed. Reload the page and try again.", "err"); });
  document.addEventListener("htmx:sendError", function () { MC.toast("Network error. Check your connection.", "err"); });

  document.addEventListener("click", function (e) {
    var c = e.target.closest("[data-copy]");
    if (c && navigator.clipboard) { navigator.clipboard.writeText(c.getAttribute("data-copy")).then(function () { MC.toast("Copied to clipboard", "ok"); }); }
  });
  document.addEventListener("change", function (e) { var s = e.target.closest("[data-autosubmit]"); if (s && s.form) s.form.requestSubmit(); });

  // Confirm dialog for destructive forms: <form data-confirm="Message" data-confirm-label="Remove">
  var pending = null;
  document.addEventListener("submit", function (e) {
    var f = e.target, msg = f.getAttribute && f.getAttribute("data-confirm"), dlg = document.getElementById("confirm");
    if (!msg || !dlg || f.__confirmed) return;
    e.preventDefault(); pending = f;
    dlg.querySelector("[data-confirm-msg]").textContent = msg;
    dlg.querySelector("[data-confirm-ok]").textContent = f.getAttribute("data-confirm-label") || "Confirm";
    dlg.showModal();
  });
  document.addEventListener("click", function (e) {
    var dlg = document.getElementById("confirm"); if (!dlg) return;
    if (e.target.closest("[data-confirm-ok]") && pending) { var f = pending; pending = null; f.__confirmed = true; dlg.close(); f.requestSubmit(); }
    if (e.target.closest("[data-confirm-cancel]")) { pending = null; dlg.close(); }
  });

  // Keyboard shortcuts (ignored while typing)
  var chord = null, GOTO = { d: "/", m: "/messages/", s: "/suppression/", i: "/identities/", p: "/config-sets/", a: "/alerts/" };
  function typing(el) { return el && (/^(input|textarea|select)$/i.test(el.tagName) || el.isContentEditable); }
  document.addEventListener("keydown", function (e) {
    if (e.metaKey || e.ctrlKey || e.altKey || typing(document.activeElement)) return;
    if (document.querySelector("dialog[open]") && e.key !== "?") return;
    if (chord) { var dest = GOTO[e.key]; chord = null; if (dest) { e.preventDefault(); location.href = dest; } return; }
    if (e.key === "g") { chord = true; setTimeout(function () { chord = null; }, 1200); }
    else if (e.key === "?") { var h = document.getElementById("shortcuts"); if (h) { e.preventDefault(); h.open ? h.close() : h.showModal(); } }
    else if (e.key === "[") { var b = document.querySelector("[data-sidebar-toggle]"); if (b) b.click(); }
  });
  document.addEventListener("click", function (e) {
    if (e.target.closest("[data-open-shortcuts]")) { var m = document.getElementById("user-menu"); if (m && m.hidePopover) m.hidePopover(); var h = document.getElementById("shortcuts"); if (h) h.showModal(); }
    var r = e.target.closest("[data-remove-address]");
    if (r) { var d = document.getElementById("remove-dialog"); if (d) { d.querySelector('input[name="addresses"]').value = r.getAttribute("data-remove-address"); d.querySelector("[data-remove-label]").textContent = r.getAttribute("data-remove-address"); d.showModal(); d.querySelector('input[name="reason"]').focus(); } }
  });
  document.addEventListener("click", function (e) { var c = e.target.closest("[data-dialog-cancel]"); if (c) c.closest("dialog").close(); });
  // Close any dialog when the backdrop is clicked.
  document.addEventListener("click", function (e) { if (e.target.tagName === "DIALOG" && e.target.open) e.target.close(); });
})();
