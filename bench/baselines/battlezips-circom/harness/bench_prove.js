#!/usr/bin/env node
// Proving / verification timing for the BattleZips-Circom baseline.
//
// Rows go to <out>/timings.csv, one per (impl, op, case, iteration):
//   impl=snarkjs-lib  : in-process snarkjs 0.4.27 API (what upstream's tests call)
//       op=wtns_calculate   snarkjs.wtns.calculate(input, wasm, {type:'mem'})  (witness generation, WASM)
//       op=groth16_prove    snarkjs.groth16.prove(zkey, wtns)                  (prover only, witness precomputed)
//       op=fullprove        snarkjs.groth16.fullProve(input, wasm, zkey)       (witness + prove)
//       op=groth16_verify   snarkjs.groth16.verify(vkey, public, proof)        (local verify)
//   impl=snarkjs-cli  : `node cli.cjs groth16 prove zkey wtns proof public` as a fresh process under
//       /usr/bin/time; wall includes Node startup + zkey load. Gives peak RSS (max_rss_kb).
//   impl=rapidsnark   : native `prover zkey wtns proof public` under /usr/bin/time (wall + peak RSS).
//       Uses the .wtns produced by snarkjs (witness gen is not included in its prove time).
// The first --warmup iterations of every in-process op are recorded with warmup=1 (they include
// curve/WASM worker initialisation) and are excluded by summarize.js.
//
// usage: node bench_prove.js --out DIR [--prove-iters 20] [--verify-iters 100] [--cli-iters 5]
//                             [--warmup 1] [--cases board,shot_hit,shot_miss] [--no-rapidsnark]
'use strict';
const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawnSync } = require('child_process');
const { upRequire, ZK, cases: getCases, csvWriter } = require('./lib');

function parseArgs(argv) {
  const a = { out: null, proveIters: 20, verifyIters: 100, cliIters: 5, warmup: 1, cases: 'board,shot_hit,shot_miss', rapidsnark: true };
  for (let i = 2; i < argv.length; i++) {
    const k = argv[i];
    const v = () => argv[++i];
    if (k === '--out') a.out = v();
    else if (k === '--prove-iters') a.proveIters = +v();
    else if (k === '--verify-iters') a.verifyIters = +v();
    else if (k === '--cli-iters') a.cliIters = +v();
    else if (k === '--warmup') a.warmup = +v();
    else if (k === '--cases') a.cases = v();
    else if (k === '--no-rapidsnark') a.rapidsnark = false;
    else throw new Error('unknown arg ' + k);
  }
  if (!a.out) throw new Error('--out required');
  return a;
}

const nowMs = () => Number(process.hrtime.bigint()) / 1e6;

// run a command under /usr/bin/time; returns {wall_ms, max_rss_kb, user_s, sys_s}
function timedSpawn(cmd, args, env) {
  const tf = path.join(os.tmpdir(), `bzt_${process.pid}_${Date.now()}.txt`);
  const t0 = nowMs();
  const r = spawnSync('/usr/bin/time', ['-f', '%M %U %S %e', '-o', tf, cmd, ...args], { encoding: 'utf8', env: env || process.env, maxBuffer: 64 << 20 });
  const wall = nowMs() - t0;
  if (r.status !== 0) {
    throw new Error(`${cmd} ${args.join(' ')} failed (${r.status}):\n${r.stdout}\n${r.stderr}`);
  }
  const [rss, user, sys] = fs.readFileSync(tf, 'utf8').trim().split(/\s+/).slice(-4);
  fs.unlinkSync(tf);
  return { wall_ms: wall.toFixed(3), max_rss_kb: rss, user_s: user, sys_s: sys };
}

async function main() {
  const args = parseArgs(process.argv);
  fs.mkdirSync(args.out, { recursive: true });
  const artDir = path.join(args.out, 'artifacts');
  fs.mkdirSync(artDir, { recursive: true });
  const snarkjs = upRequire('snarkjs');
  const allCases = await getCases();
  const caseNames = args.cases.split(',');
  const SNARKJS_CLI = process.env.SNARKJS_CLI;
  const RAPIDSNARK = process.env.RAPIDSNARK;
  const useRapid = args.rapidsnark && RAPIDSNARK && fs.existsSync(RAPIDSNARK);
  if (args.rapidsnark && !useRapid) console.error(`WARNING: rapidsnark binary not found at ${RAPIDSNARK}; skipping`);

  const csv = csvWriter(path.join(args.out, 'timings.csv'),
    ['impl', 'op', 'case', 'circuit', 'iter', 'warmup', 'wall_ms', 'max_rss_kb', 'user_s', 'sys_s', 'ok']);
  const vkeys = { board: JSON.parse(fs.readFileSync(ZK.board.vkey)), shot: JSON.parse(fs.readFileSync(ZK.shot.vkey)) };
  const log = (...m) => console.log(new Date().toISOString(), ...m);

  for (const name of caseNames) {
    const c = allCases[name];
    if (!c) throw new Error('unknown case ' + name);
    const z = ZK[c.circuit];
    const vk = vkeys[c.circuit];
    const base = { case: name, circuit: c.circuit };
    const W = args.warmup;
    log(`case ${name}: input`, JSON.stringify(c.input));
    fs.writeFileSync(path.join(artDir, `${name}_input.json`), JSON.stringify(c.input, null, 1));

    // --- witness generation (in-process) ---
    let wtns;
    for (let i = 0; i < W + args.proveIters; i++) {
      wtns = { type: 'mem' };
      const t0 = nowMs();
      await snarkjs.wtns.calculate(c.input, z.wasm, wtns);
      csv.row({ ...base, impl: 'snarkjs-lib', op: 'wtns_calculate', iter: i, warmup: +(i < W), wall_ms: (nowMs() - t0).toFixed(3), ok: 1 });
    }
    // persist the witness for the CLI / rapidsnark provers
    const wtnsFile = path.join(artDir, `${name}.wtns`);
    fs.writeFileSync(wtnsFile, Buffer.from(wtns.data));

    // --- groth16.prove (in-process, witness precomputed) ---
    let proof, publicSignals;
    for (let i = 0; i < W + args.proveIters; i++) {
      const t0 = nowMs();
      ({ proof, publicSignals } = await snarkjs.groth16.prove(z.zkey, wtns));
      const dt = nowMs() - t0;
      csv.row({ ...base, impl: 'snarkjs-lib', op: 'groth16_prove', iter: i, warmup: +(i < W), wall_ms: dt.toFixed(3), ok: 1 });
    }
    log(`  groth16.prove done; public=${JSON.stringify(publicSignals)}`);

    // --- fullProve (in-process) ---
    for (let i = 0; i < W + args.proveIters; i++) {
      const t0 = nowMs();
      ({ proof, publicSignals } = await snarkjs.groth16.fullProve(c.input, z.wasm, z.zkey));
      csv.row({ ...base, impl: 'snarkjs-lib', op: 'fullprove', iter: i, warmup: +(i < W), wall_ms: (nowMs() - t0).toFixed(3), ok: 1 });
    }
    log('  fullProve done');

    // --- verify (in-process) ---
    for (let i = 0; i < W + args.verifyIters; i++) {
      const t0 = nowMs();
      const ok = await snarkjs.groth16.verify(vk, publicSignals, proof);
      const dt = nowMs() - t0;
      if (!ok) throw new Error(`verify failed for ${name}`);
      csv.row({ ...base, impl: 'snarkjs-lib', op: 'groth16_verify', iter: i, warmup: +(i < W), wall_ms: dt.toFixed(3), ok: +ok });
    }
    log('  verify done');

    // --- snarkjs CLI prove: fresh process, peak RSS ---
    const proofF = path.join(artDir, `${name}_proof.json`);
    const pubF = path.join(artDir, `${name}_public.json`);
    for (let i = 0; i < args.cliIters; i++) {
      const r = timedSpawn(process.execPath, [SNARKJS_CLI, 'groth16', 'prove', z.zkey, wtnsFile, proofF, pubF]);
      const ok = await snarkjs.groth16.verify(vk, JSON.parse(fs.readFileSync(pubF)), JSON.parse(fs.readFileSync(proofF)));
      csv.row({ ...base, impl: 'snarkjs-cli', op: 'groth16_prove', iter: i, warmup: 0, ...r, ok: +ok });
      if (!ok) throw new Error('snarkjs CLI proof did not verify');
    }
    // CLI fullprove once per case for peak RSS including witness generation
    for (let i = 0; i < Math.min(args.cliIters, 3); i++) {
      const inF = path.join(artDir, `${name}_input.json`);
      const r = timedSpawn(process.execPath, [SNARKJS_CLI, 'groth16', 'fullprove', inF, z.wasm, z.zkey, proofF + '.fp', pubF + '.fp']);
      csv.row({ ...base, impl: 'snarkjs-cli', op: 'fullprove', iter: i, warmup: 0, ...r, ok: 1 });
    }
    log('  snarkjs CLI done');

    // --- rapidsnark (native) ---
    if (useRapid) {
      const rp = path.join(artDir, `${name}_rapidsnark_proof.json`);
      const rpub = path.join(artDir, `${name}_rapidsnark_public.json`);
      for (let i = 0; i < args.proveIters; i++) {
        const r = timedSpawn(RAPIDSNARK, [z.zkey, wtnsFile, rp, rpub]);
        let ok = '';
        if (i === 0 || i === args.proveIters - 1) {
          ok = +(await snarkjs.groth16.verify(vk, JSON.parse(fs.readFileSync(rpub)), JSON.parse(fs.readFileSync(rp))));
          if (!ok) throw new Error('rapidsnark proof did not verify');
        }
        csv.row({ ...base, impl: 'rapidsnark', op: 'groth16_prove', iter: i, warmup: 0, ...r, ok });
      }
      log('  rapidsnark done');
    }
  }
  csv.close();
  // release snarkjs' cached curve worker threads so the process exits
  if (globalThis.curve_bn128) await globalThis.curve_bn128.terminate();
}

main().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });
