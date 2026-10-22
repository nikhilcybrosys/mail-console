/* Slide-over detail drawer. Rows/links with data-drawer-url load an HTML fragment into the drawer.
   URL stays shareable via ?open=<id>; Esc/backdrop close (native <dialog>); focus returns to the row. */
(function () {
  var dlg, body, lastFocus;
  function els() { dlg = dlg || document.getElementById("drawer"); body = body || document.getElementById("drawer-body"); return !!(dlg && body); }
  function setParam(id) { var u = new URL(location.href); if (id) u.searchParams.set("open", id); else u.searchParams.delete("open"); history.replaceState(null, "", u); }
  function mark(id) { document.querySelectorAll("tr.is-active").forEach(function (r) { r.classList.remove("is-active"); }); if (id) { var r = document.querySelector('tr[data-id="' + CSS.escape(id) + '"]'); if (r) r.classList.add("is-active"); } }
  function openDrawer(url, id, trigger) {
    if (!els() || !window.htmx) { location.href = url; return; }
    lastFocus = trigger || document.activeElement;
    var pad = document.createElement("div"), sk = document.createElement("div");
    pad.className = "drawer-pad"; sk.className = "sk drawer-sk"; pad.appendChild(sk); body.replaceChildren(pad);  // loading skeleton
    if (!dlg.open) dlg.showModal();
    htmx.ajax("GET", url, { target: "#drawer-body", swap: "innerHTML" }).then(function () { setParam(id); mark(id); var f = body.querySelector("[data-autofocus],button,a,input"); if (f) f.focus(); });
  }
  document.addEventListener("click", function (e) {
    if (e.defaultPrevented || e.metaKey || e.ctrlKey || e.shiftKey || e.button) return;
    var link = e.target.closest("[data-drawer-url]");
    if (!link) {
      var row = e.target.closest("tr[data-drawer-url]");
      if (row && !e.target.closest("a,button,input,select,textarea,label")) link = row; else return;
    }
    e.preventDefault(); openDrawer(link.getAttribute("data-drawer-url"), link.getAttribute("data-id") || (link.closest("tr") || {}).getAttribute && link.closest("tr").getAttribute("data-id"), link);
  });
  document.addEventListener("close", function (e) {
    if (e.target.id !== "drawer") return; setParam(null); mark(null); if (lastFocus && lastFocus.focus) lastFocus.focus();
  }, true);
  document.addEventListener("click", function (e) { if (e.target.closest("[data-drawer-close]") && els()) dlg.close(); });
  // Tabs inside any container (works after htmx swaps): <div role="tablist"><button role="tab" aria-controls="id">
  document.addEventListener("click", function (e) {
    var tab = e.target.closest('[role="tab"]'); if (!tab) return;
    var list = tab.closest('[role="tablist"]');
    list.querySelectorAll('[role="tab"]').forEach(function (t) { var on = t === tab; t.setAttribute("aria-selected", String(on)); var p = document.getElementById(t.getAttribute("aria-controls")); if (p) p.hidden = !on; });
  });
  document.addEventListener("DOMContentLoaded", function () {
    var id = new URL(location.href).searchParams.get("open");
    if (id) { var t = document.querySelector('[data-id="' + CSS.escape(id) + '"][data-drawer-url]') || document.querySelector('tr[data-id="' + CSS.escape(id) + '"]'); if (t) openDrawer(t.getAttribute("data-drawer-url"), id, t); }
  });
})();
