/* Keyboard navigation for data tables: j/k move, Enter opens, rows with data-href navigate on click. */
(function () {
  function rows() { return Array.prototype.slice.call(document.querySelectorAll("table[data-kbd] tbody tr")); }
  function focusRow(i) { var r = rows(); if (!r.length) return; i = Math.max(0, Math.min(r.length - 1, i)); r.forEach(function (x) { x.tabIndex = -1; }); r[i].tabIndex = 0; r[i].focus(); }
  document.addEventListener("keydown", function (e) {
    if (e.metaKey || e.ctrlKey || e.altKey || /^(input|textarea|select)$/i.test((document.activeElement || {}).tagName || "") || document.querySelector("dialog[open]")) return;
    var r = rows(); if (!r.length) return;
    var cur = r.indexOf(document.activeElement.closest ? document.activeElement.closest("tr") : null);
    if (e.key === "j") { e.preventDefault(); focusRow(cur + 1); }
    else if (e.key === "k") { e.preventDefault(); focusRow(cur < 0 ? 0 : cur - 1); }
    else if (e.key === "Enter" && cur >= 0 && document.activeElement === r[cur]) { var a = r[cur].getAttribute("data-drawer-url") ? r[cur] : r[cur].querySelector("a"); if (a) a.click(); }
  });
  document.addEventListener("click", function (e) {
    var row = e.target.closest("tr[data-href]:not([data-drawer-url])"); if (row && !e.target.closest("a,button,input,select,textarea,label")) location.href = row.getAttribute("data-href");
  });
})();
