// Shared helpers for the BattleZips-Circom baseline harness (CommonJS, Node 16).
'use strict';
const path = require('path');
const fs = require('fs');
const { createRequire } = require('module');

const HARNESS_DIR = __dirname;
const BASE_DIR = path.dirname(HARNESS_DIR);
const UP_DIR = path.join(BASE_DIR, 'upstream');
// resolve deps from upstream/node_modules (the harness has no node_modules of its own)
const upRequire = createRequire(path.join(UP_DIR, 'package.json'));

const ZK = {
  board: {
    wasm: path.join(UP_DIR, 'zk/board_js/board.wasm'),
    zkey: path.join(UP_DIR, 'zk/zkey/board_final.zkey'),
    vkey: path.join(UP_DIR, 'zk/board_verification_key.json'),
    r1cs: path.join(UP_DIR, 'zk/board.r1cs'),
  },
  shot: {
    wasm: path.join(UP_DIR, 'zk/shot_js/shot.wasm'),
    zkey: path.join(UP_DIR, 'zk/zkey/shot_final.zkey'),
    vkey: path.join(UP_DIR, 'zk/shot_verification_key.json'),
    r1cs: path.join(UP_DIR, 'zk/shot.r1cs'),
  },
};

// Fixed boards and shot sequence, copied verbatim from upstream test/utils/index.js
// (x, y, z) with z = 0 horizontal, 1 vertical; ship lengths in order [5, 4, 3, 3, 2].
const boards = {
  alice: [['0', '0', '0'], ['0', '1', '0'], ['0', '2', '0'], ['0', '3', '0'], ['0', '4', '0']],
  bob:   [['1', '0', '0'], ['1', '1', '0'], ['1', '2', '0'], ['1', '3', '0'], ['1', '4', '0']],
};
// alice's 17 shots all hit bob's ships; bob's 16 shots all miss alice's ships
const shots = {
  alice: [
    [1, 0], [2, 0], [3, 0], [4, 0], [5, 0],
    [1, 1], [2, 1], [3, 1], [4, 1],
    [1, 2], [2, 2], [3, 2],
    [1, 3], [2, 3], [3, 3],
    [1, 4], [2, 4],
  ],
  bob: [
    [9, 9], [9, 8], [9, 7], [9, 6], [9, 5],
    [9, 4], [9, 3], [9, 2], [9, 1],
    [9, 0], [8, 9], [8, 8],
    [8, 7], [8, 6], [8, 5],
    [8, 4],
  ],
};

async function boardHashes() {
  const { buildMimcSponge } = upRequire('circomlibjs');
  const mimc = await buildMimcSponge();
  const F = mimc.F;
  return {
    alice: F.toObject(mimc.multiHash(boards.alice.flat())).toString(),
    bob: F.toObject(mimc.multiHash(boards.bob.flat())).toString(),
  };
}

// The three benchmark cases. shot_hit is the same input upstream test/benchmark.js uses
// (bob's board, alice's last shot [2,4]); shot_miss is bob's first shot [9,9] on alice's board.
async function cases() {
  const h = await boardHashes();
  return {
    board: { circuit: 'board', input: { ships: boards.alice, hash: h.alice } },
    shot_hit: { circuit: 'shot', input: { ships: boards.bob, hash: h.bob, shot: shots.alice[16], hit: 1 } },
    shot_miss: { circuit: 'shot', input: { ships: boards.alice, hash: h.alice, shot: shots.bob[0], hit: 0 } },
  };
}

// Same massaging upstream does in test/utils buildProofArgs (pi_b inner arrays reversed).
function buildProofArgs(proof) {
  return [
    proof.pi_a.slice(0, 2),
    proof.pi_b[0].slice(0).reverse(),
    proof.pi_b[1].slice(0).reverse(),
    proof.pi_c.slice(0, 2),
  ];
}

function csvWriter(file, header) {
  const exists = fs.existsSync(file) && fs.statSync(file).size > 0;
  const fd = fs.openSync(file, 'a');
  if (!exists) fs.writeSync(fd, header.join(',') + '\n');
  return {
    row(obj) {
      fs.writeSync(fd, header.map((k) => (obj[k] === undefined ? '' : String(obj[k]))).join(',') + '\n');
    },
    close() { fs.closeSync(fd); },
  };
}

module.exports = { HARNESS_DIR, BASE_DIR, UP_DIR, upRequire, ZK, boards, shots, boardHashes, cases, buildProofArgs, csvWriter };
