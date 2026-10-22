/* Command palette: Cmd/Ctrl+K or "/" opens it; results are a server-rendered fragment (htmx). */
(function () {
  var dlg, input;
  function open() { dlg = dlg || document.getElementById("palette"); if (!dlg) return; input = dlg.querySelector("input"); if (!dlg.open) dlg.showModal(); input.focus(); input.select(); if (window.htmx) htmx.trigger(input, "load-results"); }
  document.addEventListener("keydown", function (e) {
    var typing = /^(input|textarea|select)$/i.test((document.activeElement || {}).tagName || "");
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") { e.preventDefault(); open(); }
    else if (e.key === "/" && !typing && !document.querySelector("dialog[open]")) { e.preventDefault(); open(); }
    if (dlg && dlg.open) {
      var items = Array.prototype.slice.call(dlg.querySelectorAll(".palette-item")), cur = items.findIndex(function (i) { return i.getAttribute("aria-selected") === "true"; });
      if (e.key === "ArrowDown" || e.key === "ArrowUp") {
        e.preventDefault(); if (!items.length) return;
        var next = e.key === "ArrowDown" ? Math.min(items.length - 1, cur + 1) : Math.max(0, cur - 1);
        items.forEach(function (i) { i.removeAttribute("aria-selected"); }); items[next].setAttribute("aria-selected", "true"); items[next].scrollIntoView({ block: "nearest" });
      } else if (e.key === "Enter" && !e.isComposing) {
        var sel = items[cur >= 0 ? cur : 0]; if (sel) { e.preventDefault(); location.href = sel.getAttribute("href"); }
      }
    }
  });
  document.addEventListener("click", function (e) { if (e.target.closest("[data-open-palette]")) open(); });
  document.addEventListener("htmx:afterSwap", function (e) {
    if (e.target.id === "palette-results") { var f = e.target.querySelector(".palette-item"); if (f) f.setAttribute("aria-selected", "true"); }
  });
})();
