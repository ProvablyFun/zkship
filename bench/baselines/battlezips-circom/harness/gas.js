// Gas measurement on the in-process Hardhat network for the BattleZips-Circom baseline.
// Run from upstream/:  GAS_OUT=<dir> GAS_GAMES=1 npx hardhat run ../harness/gas.js
//
// Replays upstream test/game.js exactly (same boards, same shot sequence, same call order):
//   deploy ShotVerifier, BoardVerifier, Forwarder (ERC-2771), BattleshipGame
//   alice newGame(board proof) ; bob joinGame(board proof) ; alice firstTurn([1,0]) (no proof)
//   16 x { bob turn(hit=1 proof, next shot) ; alice turn(hit=0 proof, next shot) }
//   bob turn(hit=1 proof)  -> alice reaches 17 hits, game over (Won event)
// => 2 board proofs + 33 shot proofs (17 hit, 16 miss) + 1 proof-less firstTurn.
// Also measures a bare verifyProof() transaction to each verifier (gas of the Groth16 check itself).
// Writes <dir>/gas.csv (one row per tx) and <dir>/gas_game_totals.csv (one row per game).
'use strict';
const fs = require('fs');
const path = require('path');
const { upRequire, ZK, boards, shots, boardHashes, buildProofArgs, csvWriter } = require('./lib');
const hre = upRequire('hardhat');
const { ethers } = hre;

const OUT = process.env.GAS_OUT || path.join(__dirname, 'results', 'gas');
const GAMES = +(process.env.GAS_GAMES || 1);

// EIP-2028 calldata cost: 16 gas per non-zero byte, 4 per zero byte
function calldataGas(hex) {
  const b = Buffer.from(hex.slice(2), 'hex');
  let g = 0;
  for (const x of b) g += x === 0 ? 4 : 16;
  return { bytes: b.length, gas: g };
}

async function main() {
  fs.mkdirSync(OUT, { recursive: true });
  const snarkjs = upRequire('snarkjs');
  const H = await boardHashes();
  const vk = { board: require(ZK.board.vkey), shot: require(ZK.shot.vkey) };
  const [operator, alice, bob] = await ethers.getSigners();
  const csv = csvWriter(path.join(OUT, 'gas.csv'),
    ['game', 'seq', 'kind', 'from', 'hit', 'shot_x', 'shot_y', 'gas_used', 'calldata_bytes', 'calldata_gas', 'exec_gas', 'proof_calldata_bytes']);
  const tot = csvWriter(path.join(OUT, 'gas_game_totals.csv'),
    ['game', 'deploy_gas', 'play_gas', 'total_gas_incl_deploy', 'n_tx_play', 'n_board_proofs', 'n_shot_proofs', 'n_hit_reports', 'n_miss_reports', 'winner', 'hardfork']);
  const hardfork = hre.network.config.hardfork || hre.config.networks.hardhat.hardfork;
  console.log(`network=${hre.network.name} hardfork=${hardfork} games=${GAMES} out=${OUT}`);

  const prove = async (circuit, input) => {
    const z = ZK[circuit];
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, z.wasm, z.zkey);
    if (!(await snarkjs.groth16.verify(vk[circuit], publicSignals, proof))) throw new Error('local verify failed');
    return { proof, publicSignals, args: buildProofArgs(proof) };
  };

  for (let g = 0; g < GAMES; g++) {
    let seq = 0;
    let deployGas = 0n;
    let playGas = 0n;
    let nPlay = 0, nHit = 0, nMiss = 0, nBoard = 0;
    const record = async (kind, from, txOrReceipt, extra = {}) => {
      const tx = txOrReceipt.hash ? txOrReceipt : null;
      const rc = await txOrReceipt.wait();
      const t = tx || (await ethers.provider.getTransaction(rc.transactionHash));
      const cd = calldataGas(t.data);
      const gas = rc.gasUsed.toBigInt();
      const intrinsic = 21000n + BigInt(cd.gas) + (t.to === null ? 32000n : 0n);
      csv.row({ game: g, seq: seq++, kind, from, gas_used: gas, calldata_bytes: cd.bytes, calldata_gas: cd.gas, exec_gas: gas - intrinsic, ...extra });
      return gas;
    };
    const deploy = async (name, ...a) => {
      const f = await ethers.getContractFactory(name);
      const c = await f.deploy(...a);
      deployGas += await record(`deploy_${name}`, 'operator', c.deployTransaction);
      await c.deployed();
      return c;
    };

    // --- deployment (same order as upstream test/utils initialize()) ---
    const sv = await deploy('ShotVerifier');
    const bv = await deploy('BoardVerifier');
    const fwd = await deploy('Forwarder');
    const game = await deploy('BattleshipGame', fwd.address, bv.address, sv.address);
    const gameId = (await game.gameIndex()).toNumber() + 1;

    // --- newGame / joinGame with board proofs ---
    let p = await prove('board', { ships: boards.alice, hash: H.alice });
    playGas += await record('newGame', 'alice', await game.connect(alice).newGame(H.alice, ...p.args), { proof_calldata_bytes: 256 });
    nPlay++; nBoard++;
    // bare verifier call with the same proof (gas of the Groth16 check alone, as a tx to the verifier)
    await record('bare_BoardVerifier.verifyProof', 'operator', await operator.sendTransaction({
      to: bv.address, data: bv.interface.encodeFunctionData('verifyProof', [p.args[0], [p.args[1], p.args[2]], p.args[3], [H.alice]]),
    }), { proof_calldata_bytes: 256 });
    p = await prove('board', { ships: boards.bob, hash: H.bob });
    playGas += await record('joinGame', 'bob', await game.connect(bob).joinGame(gameId, H.bob, ...p.args), { proof_calldata_bytes: 256 });
    nPlay++; nBoard++;

    // --- opening shot (no proof) ---
    playGas += await record('firstTurn', 'alice', await game.connect(alice).firstTurn(gameId, shots.alice[0]), { shot_x: shots.alice[0][0], shot_y: shots.alice[0][1] });
    nPlay++;

    let bareShotDone = false;
    const turn = async (who, signer, board, hash, shot, hit, next) => {
      const q = await prove('shot', { ships: board, hash, shot, hit });
      if (!bareShotDone) {
        await record('bare_ShotVerifier.verifyProof', 'operator', await operator.sendTransaction({
          to: sv.address, data: sv.interface.encodeFunctionData('verifyProof', [q.args[0], [q.args[1], q.args[2]], q.args[3], q.publicSignals]),
        }), { proof_calldata_bytes: 256, hit, shot_x: shot[0], shot_y: shot[1] });
        bareShotDone = true;
      }
      const gas = await record(hit ? 'turn_hit' : 'turn_miss', who,
        await game.connect(signer).turn(gameId, !!hit, next, ...q.args), { hit, shot_x: shot[0], shot_y: shot[1], proof_calldata_bytes: 256 });
      playGas += gas; nPlay++;
      if (hit) nHit++; else nMiss++;
    };
    for (let i = 1; i <= 16; i++) {
      await turn('bob', bob, boards.bob, H.bob, shots.alice[i - 1], 1, shots.bob[i - 1]);
      await turn('alice', alice, boards.alice, H.alice, shots.bob[i - 1], 0, shots.alice[i]);
    }
    await turn('bob', bob, boards.bob, H.bob, shots.alice[16], 1, [0, 0]);

    const st = await game.gameState(gameId);
    const winner = st._winner === alice.address ? 'alice' : st._winner === bob.address ? 'bob' : 'none';
    if (winner !== 'alice') throw new Error('expected alice to win, got ' + winner);
    if (st._hitNonce[0].toNumber() !== 17) throw new Error('expected 17 hits');
    tot.row({ game: g, deploy_gas: deployGas, play_gas: playGas, total_gas_incl_deploy: deployGas + playGas, n_tx_play: nPlay,
      n_board_proofs: nBoard, n_shot_proofs: nHit + nMiss, n_hit_reports: nHit, n_miss_reports: nMiss, winner, hardfork });
    console.log(`game ${g}: deploy=${deployGas} play=${playGas} hits=${nHit} misses=${nMiss} winner=${winner}`);
  }
  csv.close(); tot.close();
  if (globalThis.curve_bn128) await globalThis.curve_bn128.terminate();
}

main().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });
