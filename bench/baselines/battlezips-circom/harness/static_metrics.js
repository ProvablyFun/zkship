#!/usr/bin/env node
// Static metrics: R1CS shape (as `snarkjs r1cs info` reports it) and artifact sizes in bytes.
// usage: node static_metrics.js --out DIR [--proof-dir DIR_WITH_bench_artifacts]
// Writes <out>/static.csv (metric,circuit,value,unit,source) and <out>/r1cs_info_<circuit>.txt.
'use strict';
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const { upRequire, ZK } = require('./lib');

async function main() {
  const argv = process.argv;
  const out = argv[argv.indexOf('--out') + 1];
  const pi = argv.indexOf('--proof-dir');
  const proofDir = pi > 0 ? argv[pi + 1] : path.join(out, 'artifacts');
  fs.mkdirSync(out, { recursive: true });
  const rows = [];
  const add = (metric, circuit, value, unit, source) => rows.push({ metric, circuit, value, unit, source });
  const snarkjs = upRequire('snarkjs');

  for (const circuit of ['board', 'shot']) {
    const z = ZK[circuit];
    // raw CLI output for provenance
    const r = spawnSync(process.execPath, [process.env.SNARKJS_CLI, 'r1cs', 'info', z.r1cs], { encoding: 'utf8' });
    fs.writeFileSync(path.join(out, `r1cs_info_${circuit}.txt`), (r.stdout + r.stderr).replace(/\x1b\[[0-9;]*m/g, ''));
    // same numbers via the snarkjs API (what `snarkjs r1cs info` prints)
    const h = await snarkjs.r1cs.info(z.r1cs);
    add('constraints', circuit, h.nConstraints, 'count', 'snarkjs r1cs info');
    add('wires', circuit, h.nVars, 'count', 'snarkjs r1cs info');
    add('public_outputs', circuit, h.nOutputs, 'count', 'snarkjs r1cs info');
    add('public_inputs', circuit, h.nPubInputs, 'count', 'snarkjs r1cs info');
    add('private_inputs', circuit, h.nPrvInputs, 'count', 'snarkjs r1cs info');
    add('labels', circuit, h.nLabels, 'count', 'snarkjs r1cs info');
    add('curve_prime_bits', circuit, h.prime.toString(2).length, 'bits', 'snarkjs r1cs info');
    for (const [k, f] of [['r1cs', z.r1cs], ['wasm', z.wasm], ['zkey_final', z.zkey], ['verification_key_json', z.vkey]]) {
      add(`size_${k}`, circuit, fs.statSync(f).size, 'bytes', path.relative(path.dirname(path.dirname(z.r1cs)), f));
    }
    const sol = path.join(path.dirname(path.dirname(z.r1cs)), 'contracts', circuit === 'board' ? 'BoardVerifier.sol' : 'ShotVerifier.sol');
    add('size_verifier_sol', circuit, fs.statSync(sol).size, 'bytes', path.basename(sol));
    // proof.json / public.json as written by `snarkjs groth16 prove` (CLI) in bench_prove.js
    const cases = circuit === 'board' ? ['board'] : ['shot_hit', 'shot_miss'];
    for (const c of cases) {
      for (const [k, f] of [['proof_json', `${c}_proof.json`], ['public_json', `${c}_public.json`], ['wtns', `${c}.wtns`]]) {
        const fp = path.join(proofDir, f);
        if (fs.existsSync(fp)) add(`size_${k}`, `${circuit}:${c}`, fs.statSync(fp).size, 'bytes', 'snarkjs CLI output');
      }
    }
    // Groth16/BN254 binary proof: A in G1, B in G2, C in G1
    add('proof_bytes_uncompressed', circuit, 2 * 32 + 4 * 32 + 2 * 32, 'bytes', 'A(G1,64)+B(G2,128)+C(G1,64); = 8 uint256 words the verifier takes');
    add('proof_bytes_compressed_theoretical', circuit, 32 + 64 + 32, 'bytes', 'point-compressed; NOT what the contract accepts');
    add('public_signals', circuit, h.nPubInputs + h.nOutputs, 'count', 'hash' + (circuit === 'shot' ? ',shot_x,shot_y,hit' : ''));
  }
  // what the game contract actually takes in calldata (ABI encoding, static types -> 32 B words)
  add('calldata_newGame', 'contract', 4 + 32 * (1 + 8), 'bytes', 'selector + boardHash + a[2],b0[2],b1[2],c[2]');
  add('calldata_joinGame', 'contract', 4 + 32 * (2 + 8), 'bytes', 'selector + gameId + boardHash + proof(8 words)');
  add('calldata_turn', 'contract', 4 + 32 * (1 + 1 + 2 + 8), 'bytes', 'selector + gameId + bool hit + next[2] + proof(8 words); boardHash & shot read from storage');
  add('calldata_firstTurn', 'contract', 4 + 32 * 3, 'bytes', 'selector + gameId + shot[2]; no proof');

  const f = path.join(out, 'static.csv');
  fs.writeFileSync(f, 'metric,circuit,value,unit,source\n' + rows.map((r) => [r.metric, r.circuit, r.value, r.unit, JSON.stringify(r.source)].join(',')).join('\n') + '\n');
  for (const r of rows) console.log(`${r.circuit.padEnd(16)} ${r.metric.padEnd(36)} ${r.value} ${r.unit}`);
}
main().then(async () => { if (globalThis.curve_bn128) await globalThis.curve_bn128.terminate(); process.exit(0); }).catch((e) => { console.error(e); process.exit(1); });
