// Soundness check of the upstream circuits: forge proofs with a modified WITNESS GENERATOR only.
// The *_evil circuits differ from upstream only in `<--` (unconstrained) assignments, so they compile
// to a byte-identical R1CS (checked by demo.sh) and the upstream zkeys / Solidity verifiers apply.
// Run from upstream/:  npx hardhat run ../harness/soundness/demo.js   (via demo.sh)
'use strict';
const fs = require('fs');
const path = require('path');
const { upRequire, ZK, boards, shots, boardHashes, buildProofArgs } = require('../lib');
const hre = upRequire('hardhat');
const { ethers } = hre;

const B = path.join(__dirname, 'build');

async function main() {
  const snarkjs = upRequire('snarkjs');
  const { buildMimcSponge } = upRequire('circomlibjs');
  const mimc = await buildMimcSponge();
  const H = await boardHashes();
  const vk = { board: require(ZK.board.vkey), shot: require(ZK.shot.vkey) };
  const sv = await (await ethers.getContractFactory('ShotVerifier')).deploy();
  const bv = await (await ethers.getContractFactory('BoardVerifier')).deploy();
  const out = {};

  const tryHonest = async (input, wasm) => {
    try { await snarkjs.wtns.calculate(input, wasm, { type: 'mem' }); return 'witness computed (unexpected)'; } catch (e) { return 'rejected: ' + String(e.message || e).split('\n')[0]; }
  };
  const forge = async (circuit, input, evilWasm) => {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, evilWasm, ZK[circuit].zkey); // HONEST zkey
    const local = await snarkjs.groth16.verify(vk[circuit], publicSignals, proof); // HONEST vkey
    const a = buildProofArgs(proof);
    const onchain = circuit === 'board'
      ? await bv.verifyProof(a[0], [a[1], a[2]], a[3], publicSignals)
      : await sv.verifyProof(a[0], [a[1], a[2]], a[3], publicSignals);
    return { publicSignals, snarkjs_verify: local, solidity_verifyProof: onchain };
  };

  // 1) Shot: alice's shot [2,4] HITS bob's 2-long ship at (1,4)-(2,4). Claim a MISS (hit = 0).
  const shotIn = { ships: boards.bob, hash: H.bob, shot: shots.alice[16], hit: 0 };
  out.shot_false_miss = {
    claim: 'shot [2,4] on bob board reported as MISS although it hits ship #5 at (1,4) horizontal',
    honest_wasm: await tryHonest(shotIn, ZK.shot.wasm),
    forged: await forge('shot', shotIn, path.join(B, 'shot_evil_js/shot_evil.wasm')),
  };
  // 1b) Shot: bob's shot [9,9] misses alice's board. Claim a HIT (hit = 1) -> OR() inputs are unconstrained too.
  // (needs the witness generator to output 1; the evil HitShip outputs 0, so this case is only argued, not run)

  // 2) Board: all five ships stacked on top of each other at (0,0) horizontal.
  const stacked = [['0', '0', '0'], ['0', '0', '0'], ['0', '0', '0'], ['0', '0', '0'], ['0', '0', '0']];
  const hStacked = mimc.F.toObject(mimc.multiHash(stacked.flat())).toString();
  const boardIn = { ships: stacked, hash: hStacked };
  out.board_overlapping = {
    claim: 'all 5 ships placed at (0,0) horizontal, i.e. fully overlapping (5 occupied cells instead of 17)',
    honest_wasm: await tryHonest(boardIn, ZK.board.wasm),
    forged: await forge('board', boardIn, path.join(B, 'board_evil_js/board_evil.wasm')),
  };

  fs.writeFileSync(path.join(__dirname, 'result.json'), JSON.stringify(out, null, 2));
  console.log(JSON.stringify(out, null, 2));
  if (globalThis.curve_bn128) await globalThis.curve_bn128.terminate();
}
main().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });
