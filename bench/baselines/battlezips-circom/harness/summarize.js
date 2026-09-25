#!/usr/bin/env node
// Aggregate raw CSVs of one run directory into summary.json (median / p95 / mean / min / max / n).
// Warm-up rows (warmup=1) are excluded from timing statistics. p95 uses the nearest-rank method.
// usage: node summarize.js DIR
'use strict';
const fs = require('fs');
const path = require('path');

const dir = process.argv[2];
if (!dir) { console.error('usage: summarize.js DIR'); process.exit(2); }

function readCsv(f) {
  if (!fs.existsSync(f)) return [];
  const [head, ...lines] = fs.readFileSync(f, 'utf8').trim().split('\n');
  const keys = head.split(',');
  return lines.filter(Boolean).map((l) => {
    const v = l.split(',');
    return Object.fromEntries(keys.map((k, i) => [k, v[i]]));
  });
}
function stats(xs) {
  const s = xs.map(Number).filter((x) => Number.isFinite(x)).sort((a, b) => a - b);
  const n = s.length;
  if (!n) return { n: 0 };
  const q = (p) => s[Math.min(n - 1, Math.max(0, Math.ceil(p * n) - 1))];
  const med = n % 2 ? s[(n - 1) / 2] : (s[n / 2 - 1] + s[n / 2]) / 2;
  const mean = s.reduce((a, b) => a + b, 0) / n;
  return { n, median: +med.toFixed(3), p95: +q(0.95).toFixed(3), mean: +mean.toFixed(3), min: s[0], max: s[n - 1] };
}
function groupBy(rows, keyf) {
  const m = new Map();
  for (const r of rows) { const k = keyf(r); if (!m.has(k)) m.set(k, []); m.get(k).push(r); }
  return m;
}

const summary = { run_dir: path.resolve(dir), generated: new Date().toISOString() };

const envf = path.join(dir, 'env.json');
if (fs.existsSync(envf)) summary.env = JSON.parse(fs.readFileSync(envf, 'utf8'));

// ---- static
summary.static = {};
for (const r of readCsv(path.join(dir, 'static.csv'))) {
  (summary.static[r.circuit] ||= {})[r.metric] = Number(r.value);
}

// ---- timings
const t = readCsv(path.join(dir, 'timings.csv')).filter((r) => r.warmup !== '1');
summary.timings_ms = {};
for (const [k, rows] of groupBy(t, (r) => `${r.impl}|${r.op}|${r.case}`)) {
  const [impl, op, c] = k.split('|');
  const e = { wall_ms: stats(rows.map((r) => r.wall_ms)) };
  if (rows.some((r) => r.max_rss_kb)) e.max_rss_kb = stats(rows.map((r) => r.max_rss_kb));
  ((summary.timings_ms[c] ||= {})[impl] ||= {})[op] = e;
}

// ---- gas
const g = readCsv(path.join(dir, 'gas.csv'));
summary.gas = { per_tx_kind: {}, games: readCsv(path.join(dir, 'gas_game_totals.csv')) };
for (const [kind, rows] of groupBy(g, (r) => r.kind)) {
  summary.gas.per_tx_kind[kind] = {
    gas_used: stats(rows.map((r) => r.gas_used)),
    exec_gas: stats(rows.map((r) => r.exec_gas)),
    calldata_bytes: stats(rows.map((r) => r.calldata_bytes)),
    calldata_gas: stats(rows.map((r) => r.calldata_gas)),
  };
}
if (summary.gas.games.length) {
  const G = summary.gas.games;
  summary.gas.game_total = {
    deploy_gas: stats(G.map((r) => r.deploy_gas)),
    play_gas: stats(G.map((r) => r.play_gas)),
    total_gas_incl_deploy: stats(G.map((r) => r.total_gas_incl_deploy)),
  };
}

// ---- setup (one-time build rows, copied if present)
const sf = path.join(dir, 'setup_times.csv');
if (fs.existsSync(sf)) summary.setup_build_time_s = readCsv(sf);

fs.writeFileSync(path.join(dir, 'summary.json'), JSON.stringify(summary, null, 2));

// short human-readable table
const lines = [];
for (const [c, impls] of Object.entries(summary.timings_ms)) {
  for (const [impl, ops] of Object.entries(impls)) {
    for (const [op, e] of Object.entries(ops)) {
      const w = e.wall_ms;
      lines.push(`${c.padEnd(10)} ${impl.padEnd(12)} ${op.padEnd(15)} n=${String(w.n).padStart(3)} median=${String(w.median).padStart(9)} ms p95=${String(w.p95).padStart(9)} ms` +
        (e.max_rss_kb ? `  peakRSS median=${Math.round(e.max_rss_kb.median / 1024)} MiB` : ''));
    }
  }
}
for (const [k, e] of Object.entries(summary.gas.per_tx_kind)) {
  lines.push(`gas ${k.padEnd(32)} n=${String(e.gas_used.n).padStart(3)} median=${e.gas_used.median} (calldata ${e.calldata_bytes.median} B)`);
}
if (summary.gas.game_total) {
  lines.push(`gas full game: play=${summary.gas.game_total.play_gas.median} deploy=${summary.gas.game_total.deploy_gas.median} total=${summary.gas.game_total.total_gas_incl_deploy.median}`);
}
fs.writeFileSync(path.join(dir, 'summary.txt'), lines.join('\n') + '\n');
console.log(lines.join('\n'));
