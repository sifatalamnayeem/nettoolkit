"use strict";

// All dynamic text goes through textContent (never innerHTML), so target names
// and error messages coming from the database cannot inject markup.

const SVG_NS = "http://www.w3.org/2000/svg";
const REFRESH_MS = 30000;

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function svgEl(tag, attrs, text) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [key, value] of Object.entries(attrs || {})) node.setAttribute(key, value);
  if (text !== undefined) node.textContent = text;
  return node;
}

async function getJSON(url) {
  const res = await fetch(url, { cache: "no-store" });
  if (!res.ok) throw new Error(`${url} returned ${res.status}`);
  return res.json();
}

function fmt(value, digits = 1) {
  return value === null || value === undefined ? "-" : Number(value).toFixed(digits);
}

function timeLabel(ms, spanMs) {
  const d = new Date(ms);
  return spanMs > 36 * 3600 * 1000
    ? d.toLocaleDateString([], { month: "short", day: "numeric" })
    : d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

/**
 * Line chart. series = [{ label, className, points: [{ x: ms, y: number|null }] }].
 * Gaps (y === null) break the line instead of being drawn as zero.
 */
function lineChart(container, series, ariaLabel) {
  container.replaceChildren();
  const all = series.flatMap((s) => s.points.filter((p) => p.y !== null));
  if (all.length === 0) {
    container.append(el("p", "empty", "No data yet"));
    return;
  }

  const W = 600, H = 170;
  const pad = { l: 44, r: 10, t: 10, b: 22 };
  const xs = all.map((p) => p.x);
  const xmin = Math.min(...xs);
  const xmax = Math.max(...xs);
  const ymax = (Math.max(...all.map((p) => p.y)) || 1) * 1.1;
  const sx = (x) => pad.l + (xmax === xmin ? 0.5 : (x - xmin) / (xmax - xmin)) * (W - pad.l - pad.r);
  const sy = (y) => H - pad.b - (y / ymax) * (H - pad.t - pad.b);

  const root = svgEl("svg", { viewBox: `0 0 ${W} ${H}`, class: "chart", role: "img", "aria-label": ariaLabel });

  for (let i = 0; i <= 4; i++) {
    const value = (ymax * i) / 4;
    const y = sy(value);
    root.append(svgEl("line", { x1: pad.l, x2: W - pad.r, y1: y, y2: y, class: "gridline" }));
    root.append(svgEl("text", { x: pad.l - 6, y: y + 4, "text-anchor": "end" }, value >= 10 ? value.toFixed(0) : value.toFixed(1)));
  }
  root.append(svgEl("text", { x: pad.l, y: H - 5, "text-anchor": "start" }, timeLabel(xmin, xmax - xmin)));
  root.append(svgEl("text", { x: W - pad.r, y: H - 5, "text-anchor": "end" }, timeLabel(xmax, xmax - xmin)));

  series.forEach((s) => {
    const segments = [];
    let current = [];
    for (const p of s.points) {
      if (p.y === null) {
        if (current.length) segments.push(current);
        current = [];
      } else {
        current.push(p);
      }
    }
    if (current.length) segments.push(current);

    for (const seg of segments) {
      if (seg.length === 1) {
        root.append(svgEl("circle", { cx: sx(seg[0].x), cy: sy(seg[0].y), r: 2.5, class: `dot ${s.className}` }));
      } else {
        const d = seg.map((p, i) => `${i ? "L" : "M"}${sx(p.x).toFixed(1)},${sy(p.y).toFixed(1)}`).join(" ");
        root.append(svgEl("path", { d, class: `line ${s.className}` }));
      }
    }
  });

  container.append(root);
}

/** Row of small bars, one per check: green = up, red = down. */
function uptimeStrip(points) {
  const recent = points.slice(-90);
  const W = 300, H = 22;
  const root = svgEl("svg", { viewBox: `0 0 ${W} ${H}`, class: "strip", preserveAspectRatio: "none", role: "img", "aria-label": "Recent check results" });
  const step = W / Math.max(recent.length, 1);
  recent.forEach((p, i) => {
    root.append(svgEl("rect", { x: i * step, y: 0, width: Math.max(step - 1, 1), height: H, rx: 1, class: p.up ? "ok" : "bad" }));
  });
  return root;
}

function targetCard(t, series) {
  const card = el("article", "card");
  const head = el("div", "card-head");
  head.append(el("h3", "", t.name), el("span", `badge ${t.up ? "up" : "down"}`, t.up ? "UP" : "DOWN"));

  const stats = el("div", "stats");
  const uptime = el("div");
  uptime.append(el("strong", "", t.uptime_pct === null ? "-" : `${fmt(t.uptime_pct, 2)}%`), document.createTextNode("uptime"));
  const latency = el("div");
  latency.append(el("strong", "", t.avg_latency_ms === null ? "-" : `${fmt(t.avg_latency_ms)} ms`), document.createTextNode("avg latency"));
  const checks = el("div");
  checks.append(el("strong", "", String(t.checks)), document.createTextNode("checks"));
  stats.append(uptime, latency, checks);

  card.append(head, stats, uptimeStrip(series.points));

  const chart = el("div");
  lineChart(
    chart,
    [{ label: "Latency", className: "s0", points: series.points.map((p) => ({ x: Date.parse(p.ts), y: p.latency_ms })) }],
    `Latency of ${t.name} in milliseconds`,
  );
  card.append(chart);
  card.append(el("p", "detail", `${t.kind.toUpperCase()}: ${t.detail || ""}`));
  return card;
}

function renderSpeed(speed, points) {
  const tiles = document.getElementById("speed-tiles");
  tiles.replaceChildren();
  const latest = speed.latest;
  const avg = speed.averages;
  const items = [
    ["Download", latest && latest.download_mbps, "Mbps", avg && avg.download_mbps],
    ["Upload", latest && latest.upload_mbps, "Mbps", avg && avg.upload_mbps],
    ["Ping", latest && latest.ping_ms, "ms", avg && avg.ping_ms],
  ];
  for (const [label, value, unit, average] of items) {
    const tile = el("div", "tile");
    const v = el("div", "value", fmt(value, 1));
    v.append(document.createTextNode(" "), el("span", "unit", unit));
    tile.append(el("div", "label", `${label} (latest)`), v, el("div", "label", `avg ${fmt(average, 1)} ${unit}`));
    tiles.append(tile);
  }

  const x = (p) => Date.parse(p.ts);
  lineChart(
    document.getElementById("chart-throughput"),
    [
      { label: "Download", className: "s0", points: points.map((p) => ({ x: x(p), y: p.download_mbps })) },
      { label: "Upload", className: "s1", points: points.map((p) => ({ x: x(p), y: p.upload_mbps })) },
    ],
    "Download and upload speed in megabits per second",
  );
  lineChart(
    document.getElementById("chart-ping"),
    [{ label: "Ping", className: "s0", points: points.map((p) => ({ x: x(p), y: p.ping_ms })) }],
    "Ping in milliseconds",
  );

  const legend = document.getElementById("legend-throughput");
  legend.replaceChildren();
  for (const [label, cls] of [["Download", "s0"], ["Upload", "s1"]]) {
    const item = el("span");
    item.append(el("span", `sw ${cls}`), document.createTextNode(label));
    legend.append(item);
  }
}

let loading = false;

async function refresh() {
  if (loading) return;
  loading = true;
  const hours = Number(document.getElementById("hours").value);
  const errorBox = document.getElementById("error");
  try {
    const [overview, speed] = await Promise.all([
      getJSON(`/api/overview?hours=${hours}`),
      getJSON("/api/speed?limit=200"),
    ]);
    const seriesList = await Promise.all(
      overview.targets.map((t) => getJSON(`/api/series?target=${encodeURIComponent(t.name)}&hours=${hours}`)),
    );

    const container = document.getElementById("targets");
    container.replaceChildren();
    if (overview.targets.length === 0) {
      container.append(el("p", "empty", "No checks yet. Run `nettool monitor run` or `nettool dashboard --demo`."));
    }
    overview.targets.forEach((t, i) => container.append(targetCard(t, seriesList[i])));

    const down = overview.targets.filter((t) => !t.up).length;
    document.getElementById("summary").textContent = overview.targets.length
      ? down ? `${down} of ${overview.targets.length} targets down` : `All ${overview.targets.length} targets up`
      : "";

    renderSpeed(overview.speed, speed.points);
    document.getElementById("updated").textContent = `Updated ${new Date().toLocaleTimeString()}`;
    errorBox.hidden = true;
  } catch (err) {
    errorBox.textContent = `Could not load data: ${err.message}`;
    errorBox.hidden = false;
  } finally {
    loading = false;
  }
}

document.getElementById("hours").addEventListener("change", refresh);
refresh();
setInterval(refresh, REFRESH_MS);
