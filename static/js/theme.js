/* Loaded synchronously in <head> (external file, so no inline script is needed under the CSP):
   applies theme / density / sidebar state before first paint, so there is no flash. */
(function () {
  var root = document.documentElement, ls = {
    get: function (k) { try { return localStorage.getItem(k); } catch (e) { return null; } },
    set: function (k, v) { try { localStorage.setItem(k, v); } catch (e) {} }
  };
  var mq = window.matchMedia ? matchMedia("(prefers-color-scheme: dark)") : null;
  function resolve(pref) { return pref === "dark" || (pref !== "light" && mq && mq.matches) ? "dark" : "light"; }
  function applyTheme() {
    var pref = ls.get("mc-theme") || root.getAttribute("data-default-theme") || "system";
    root.setAttribute("data-theme", resolve(pref));
    root.setAttribute("data-theme-pref", pref);
    document.dispatchEvent(new CustomEvent("mc:theme"));
  }
  function applyDensity() { root.setAttribute("data-density", (ls.get("mc-density") || root.getAttribute("data-default-density")) === "comfortable" ? "comfortable" : "compact"); }
  function applySidebar() { if (ls.get("mc-sidebar") === "collapsed") root.setAttribute("data-sidebar", "collapsed"); else root.removeAttribute("data-sidebar"); }
  applyTheme(); applyDensity(); applySidebar();
  if (mq && mq.addEventListener) mq.addEventListener("change", function () { if ((ls.get("mc-theme") || root.getAttribute("data-default-theme") || "system") === "system") applyTheme(); });

  document.addEventListener("click", function (e) {
    var t = e.target.closest("[data-theme-set]"), d = e.target.closest("[data-density-set]"), s = e.target.closest("[data-sidebar-toggle]"), n = e.target.closest("[data-nav-toggle]");
    if (t) { ls.set("mc-theme", t.getAttribute("data-theme-set")); applyTheme(); syncPressed(); }
    if (d) { ls.set("mc-density", d.getAttribute("data-density-set")); applyDensity(); syncPressed(); }
    if (s) { ls.set("mc-sidebar", root.getAttribute("data-sidebar") === "collapsed" ? "expanded" : "collapsed"); applySidebar(); }
    if (n) { root.setAttribute("data-nav-open", root.getAttribute("data-nav-open") === "1" ? "0" : "1"); }
    else if (root.getAttribute("data-nav-open") === "1" && !e.target.closest(".sidebar")) root.setAttribute("data-nav-open", "0");
  });
  function syncPressed() {
    var pref = root.getAttribute("data-theme-pref"), den = root.getAttribute("data-density");
    document.querySelectorAll("[data-theme-set]").forEach(function (b) { b.setAttribute("aria-checked", String(b.getAttribute("data-theme-set") === pref)); });
    document.querySelectorAll("[data-density-set]").forEach(function (b) { b.setAttribute("aria-checked", String(b.getAttribute("data-density-set") === den)); });
  }
  document.addEventListener("DOMContentLoaded", syncPressed);
  window.MC = window.MC || {};
})();
