/* Time-series chart (uPlot). Data arrives as JSON in a <script type="application/json"> element
   (json_script), which the CSP does not treat as executable. No eval, no inline handlers. */
(function () {
  function css(name) { return getComputedStyle(document.documentElement).getPropertyValue(name).trim(); }
  function build(box) {
    var data = JSON.parse(document.getElementById(box.getAttribute("data-chart")).textContent);
    if (!window.uPlot || !data.x || !data.x.length) return;
    box.replaceChildren();
    var tip = document.createElement("div"); tip.className = "chart-tip"; tip.hidden = true; box.parentNode.appendChild(tip);
    var colors = data.series.map(function (s) { return css(s.color); }), grid = css("--chart-grid"), ink = css("--muted");
    var hidden = {}; (box.__hidden || []).forEach(function (k) { hidden[k] = 1; });
    var opts = {
      width: box.clientWidth, height: 260, legend: { show: false }, padding: [8, 8, 0, 0],
      cursor: { points: { size: 7 }, drag: { x: false, y: false } },
      scales: { x: { time: true } },
      axes: [{ stroke: ink, grid: { stroke: grid, width: 1 }, ticks: { show: false }, font: "11px Geist, system-ui" },
             { stroke: ink, grid: { stroke: grid, width: 1 }, ticks: { show: false }, size: 44, font: "11px Geist, system-ui" }],
      series: [{}].concat(data.series.map(function (s, i) { return { label: s.label, stroke: colors[i], width: 2, show: !hidden[s.key], points: { show: false }, fill: i === 0 ? colors[i] + "22" : undefined }; })),
      hooks: { setCursor: [function (u) {
        var i = u.cursor.idx; if (i == null) { tip.hidden = true; return; }
        tip.hidden = false; tip.textContent = "";
        var h = document.createElement("b"); h.textContent = new Date(data.x[i] * 1000).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }); tip.appendChild(h);
        data.series.forEach(function (s, k) { if (u.series[k + 1].show) { var d = document.createElement("div"), l = document.createElement("span"), v = document.createElement("b"); l.textContent = s.label; v.textContent = String(s.values[i]); d.appendChild(l); d.appendChild(v); tip.appendChild(d); } });
        var left = Math.min(u.cursor.left + 16, box.clientWidth - tip.offsetWidth - 8); tip.style.left = Math.max(8, left) + "px"; tip.style.top = "16px";
      }] }
    };
    var u = new uPlot(opts, [data.x].concat(data.series.map(function (s) { return s.values; })), box);
    box.__plot = u; box.__tip = tip;
    var legend = document.querySelector('[data-legend-for="' + box.getAttribute("data-chart") + '"]');
    if (legend) legend.onclick = function (e) {
      var b = e.target.closest("[data-series]"); if (!b) return;
      var idx = data.series.findIndex(function (s) { return s.key === b.getAttribute("data-series"); }), on = b.getAttribute("aria-pressed") !== "true";
      b.setAttribute("aria-pressed", String(on)); u.setSeries(idx + 1, { show: on });
      box.__hidden = data.series.filter(function (s, k) { return !u.series[k + 1].show; }).map(function (s) { return s.key; });
    };
  }
  function init() { document.querySelectorAll("[data-chart]").forEach(function (box) { build(box); if (window.ResizeObserver && !box.__ro) { box.__ro = new ResizeObserver(function () { if (box.__plot) box.__plot.setSize({ width: box.clientWidth, height: 260 }); }); box.__ro.observe(box); } }); }
  document.addEventListener("DOMContentLoaded", init);
  document.addEventListener("mc:theme", function () { document.querySelectorAll("[data-chart]").forEach(function (box) { if (box.__plot) { box.__plot.destroy(); if (box.__tip) box.__tip.remove(); build(box); } }); });
})();
