'use strict';
// Global admin-command idempotency. A commandId used successfully by ANY admin
// command (adjudicate / rotate / compact) is reserved across every command
// type and every device:
//   * same commandId + same kind + same content replays the first response;
//   * reuse for a different kind or different content is a stable 409;
//   * two API instances contending for one commandId produce exactly one first
//     result and the loser rolls back without any partial write;
//   * a command that FAILS reserves nothing, so its commandId stays free.

import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { setupHarness, stopTestPostgres, truncateAll } from './helpers/harness.mjs';
import { createPool } from '../src/db/pool.mjs';
import { registerDevice, rotateKey, getDevice } from '../src/services/devices.mjs';
import { ingestBatch } from '../src/services/ingest.mjs';
import { adjudicate, getConflict } from '../src/services/conflicts.mjs';
import { compactDevice } from '../src/services/compaction.mjs';
import { DeviceSigner, buildChain, prepareBatch } from './helpers/events.mjs';
import { buildEnvelope } from '../src/crypto/envelope.js';
import { ApiError } from '../src/errors.mjs';

let h;
before(async () => { h = await setupHarness(); });
after(async () => { await h.pool.end(); await stopTestPostgres(); });
beforeEach(async () => { await truncateAll(h.pool); });

const ingest = (deviceId, requestId, events) =>
  ingestBatch(h.pool, prepareBatch(deviceId, requestId, events));

/** Create a device with an open, adjudicable conflict at conflictSeq. */
async function deviceWithOpenConflict(id, conflictSeq = 3, total = conflictSeq) {
  const signer = new DeviceSigner();
  await registerDevice(h.pool, { deviceId: id, publicKeyRaw: signer.publicRaw });
  const chain = buildChain(signer, id, total);
  // A divergent candidate at the conflict sequence, then the honest chain.
  const fork = structuredClone(chain[conflictSeq - 1]);
  fork.eventId = `fork-${conflictSeq}`;
  fork.payload = { fork: true };
  const { bytes } = buildEnvelope(fork);
  const { signBytes, encodeB64Url } = await import('../src/crypto/keys.js');
  fork.signature = encodeB64Url(signBytes(signer.privateKey, bytes));

  await ingest(id, `${id}-fork`, [fork]);
  const pre = await ingest(id, `${id}-real`, [chain[conflictSeq - 1]]);
  const prefix = chain.filter((e) => e.sequence < conflictSeq);
  if (prefix.length) await ingest(id, `${id}-fill`, prefix);
  // Any honest tail beyond the conflict stays unstaged until the conflict is
  // resolved; callers ingest it afterwards when they need a higher watermark.
  const info = pre.conflicts.find((c) => c.sequence === conflictSeq);
  assert.equal(info.reason, 'divergent_candidates');
  return { signer, chain, revision: info.revision };
}

async function assertConflict(p, code = 'IDEMPOTENCY_CONFLICT') {
  const e = await p.then(() => null, (err) => err);
  assert.ok(e instanceof ApiError, `expected ApiError, got ${e}`);
  assert.equal(e.code, code);
  assert.equal(e.status, 409);
  return e;
}

test('reported scenario: reuse after adjudication makes rotation a stable 409, never 500', async () => {
  const id = 'dev-xkind-repro';
  const { signer, chain, revision } = await deviceWithOpenConflict(id, 3);
  const commandId = 'cmd-after-adjudicate';

  const adj = await adjudicate(h.pool, {
    deviceId: id, sequence: 3, commandId,
    expectedConflictRevision: revision,
    decision: { type: 'select', digest: buildEnvelope(chain[2]).digest },
  });
  assert.equal(adj.replayed, false);
  assert.equal(adj.highWatermark, 3);

  const k2 = new DeviceSigner();
  const rotP = rotateKey(h.pool, {
    deviceId: id, commandId, keyVersion: 2,
    effectiveSequence: 9, expectedControlRevision: 1, publicKeyRaw: k2.publicRaw,
  });
  const e = await assertConflict(rotP);
  // Structured details identify the first command.
  assert.equal(e.details.existingKind, 'adjudicate');
  assert.equal(e.details.existingDeviceId, id);
  assert.equal(e.details.requestedKind, 'rotate');
  assert.equal(e.details.commandId, commandId);

  // The error is stable on repeat and never becomes a 500.
  await assertConflict(rotateKey(h.pool, {
    deviceId: id, commandId, keyVersion: 2,
    effectiveSequence: 9, expectedControlRevision: 1, publicKeyRaw: k2.publicRaw,
  }));

  // No partial rotation: revision stays 1, only key generation 1 exists.
  const state = await getDevice(h.pool, id);
  assert.equal(state.controlRevision, 1);
  assert.deepEqual(state.keys.map((k) => k.keyVersion), [1]);

  // The device is still fully usable: a fresh commandId rotates normally.
  const rot = await rotateKey(h.pool, {
    deviceId: id, commandId: 'cmd-fresh', keyVersion: 2,
    effectiveSequence: 9, expectedControlRevision: 1, publicKeyRaw: k2.publicRaw,
  });
  assert.equal(rot.controlRevision, 2);
  assert.equal(rot.replayed, false);
});

test('full cross-kind matrix: each ordered kind pair conflicts; same-kind same content replays', async () => {
  const id = 'dev-matrix';
  const { chain } = await deviceWithOpenConflict(id, 2, 6);
  // Conflict at 2 blocks promotion; seq 1 is visible, seq 3..6 arrive later.
  const digest2 = buildEnvelope(chain[1]).digest;
  const adjId = 'm-adj';
  const rotId = 'm-rot';
  const cpId = 'm-cp';

  // First commands, in an order that keeps every payload valid.
  const adj = await adjudicate(h.pool, {
    deviceId: id, sequence: 2, commandId: adjId, expectedConflictRevision: 1,
    decision: { type: 'select', digest: digest2 },
  });
  assert.equal(adj.resolution, 'selected');
  assert.equal(adj.highWatermark, 2);
  // Release the blocked tail.
  await ingest(id, `${id}-tail`, chain.slice(2));
  assert.equal((await getDevice(h.pool, id)).highWatermark, 6);

  const k2 = new DeviceSigner();
  const rotCmd = {
    deviceId: id, commandId: rotId, keyVersion: 2,
    effectiveSequence: 8, expectedControlRevision: 1, publicKeyRaw: k2.publicRaw,
  };
  await rotateKey(h.pool, rotCmd);

  const cp = await compactDevice(h.pool, h.serverKey, h.cfg, id, 3, cpId);
  assert.equal(cp.checkpoint.sequence, 3);

  // Same kind + identical content replays the stored first response.
  const adjAgain = await adjudicate(h.pool, {
    deviceId: id, sequence: 2, commandId: adjId, expectedConflictRevision: 1,
    decision: { type: 'select', digest: digest2 },
  });
  assert.equal(adjAgain.replayed, true);
  assert.equal(adjAgain.resolution, 'selected');
  const rotAgain = await rotateKey(h.pool, rotCmd);
  assert.equal(rotAgain.replayed, true);
  assert.equal(rotAgain.controlRevision, 2);
  const cpAgain = await compactDevice(h.pool, h.serverKey, h.cfg, id, 3, cpId);
  assert.equal(cpAgain.replayed, true);

  // Same kind + different content conflicts (existing behavior preserved).
  await assertConflict(adjudicate(h.pool, {
    deviceId: id, sequence: 2, commandId: adjId, expectedConflictRevision: 1,
    decision: { type: 'reject_all' },
  }));
  await assertConflict(rotateKey(h.pool, { ...rotCmd, publicKeyRaw: new DeviceSigner().publicRaw }));
  await assertConflict(compactDevice(h.pool, h.serverKey, h.cfg, id, 2, cpId));

  // Cross-kind reuse conflicts in BOTH directions for every pair.
  const otherKey = new DeviceSigner();
  const crossRotate = (commandId) => rotateKey(h.pool, {
    deviceId: id, commandId, keyVersion: 3, effectiveSequence: 12,
    expectedControlRevision: 2, publicKeyRaw: otherKey.publicRaw,
  });
  const crossAdjudicate = (commandId) => adjudicate(h.pool, {
    deviceId: id, sequence: 2, commandId, expectedConflictRevision: 1,
    decision: { type: 'select', digest: digest2 },
  });
  const crossCompact = (commandId) => compactDevice(h.pool, h.serverKey, h.cfg, id, 2, commandId);

  let err = await assertConflict(crossRotate(adjId));
  assert.equal(err.details.existingKind, 'adjudicate');
  err = await assertConflict(crossCompact(adjId));
  assert.equal(err.details.existingKind, 'adjudicate');

  err = await assertConflict(crossAdjudicate(rotId));
  assert.equal(err.details.existingKind, 'rotate');
  err = await assertConflict(crossCompact(rotId));
  assert.equal(err.details.existingKind, 'rotate');

  err = await assertConflict(crossAdjudicate(cpId));
  assert.equal(err.details.existingKind, 'compact');
  err = await assertConflict(crossRotate(cpId));
  assert.equal(err.details.existingKind, 'compact');

  // Conflicts never applied anything: exactly one rotation, one checkpoint.
  const state = await getDevice(h.pool, id);
  assert.equal(state.controlRevision, 2);
  assert.deepEqual(state.keys.map((k) => k.keyVersion), [1, 2]);
  const { rows: cps } = await h.pool.query(
    'SELECT count(*)::int AS n FROM checkpoints WHERE device_id=$1', [id]
  );
  assert.equal(cps[0].n, 1);
  const { rows: cmds } = await h.pool.query(
    'SELECT kind, count(*)::int AS n FROM admin_commands GROUP BY kind ORDER BY kind'
  );
  assert.deepEqual(cmds.map((r) => [r.kind, r.n]), [['adjudicate', 1], ['compact', 1], ['rotate', 1]]);
});

test('a FAILED command reserves nothing; its commandId stays free for another type', async () => {
  const id = 'dev-failed-free';
  const { chain, revision } = await deviceWithOpenConflict(id, 3);

  // Stale revision: the adjudication fails (409) and commits no reservation.
  await assertConflict(
    adjudicate(h.pool, {
      deviceId: id, sequence: 3, commandId: 'reuse-after-fail',
      expectedConflictRevision: revision + 40,
      decision: { type: 'select', digest: buildEnvelope(chain[2]).digest },
    }),
    'CONFLICT_REVISION_MISMATCH'
  );
  const { rows: n1 } = await h.pool.query(
    'SELECT count(*)::int AS n FROM admin_commands WHERE command_id=$1', ['reuse-after-fail']
  );
  assert.equal(n1[0].n, 0);

  // The same commandId then succeeds for a rotation.
  const k2 = new DeviceSigner();
  const rot = await rotateKey(h.pool, {
    deviceId: id, commandId: 'reuse-after-fail', keyVersion: 2,
    effectiveSequence: 9, expectedControlRevision: 1, publicKeyRaw: k2.publicRaw,
  });
  assert.equal(rot.replayed, false);
  assert.equal(rot.controlRevision, 2);

  // A failing rotation leaves the id free for an adjudication on a second
  // device.
  const id2 = 'dev-failed-free-2';
  const setup2 = await deviceWithOpenConflict(id2, 2, 2);
  await assertConflict(
    rotateKey(h.pool, {
      deviceId: id2, commandId: 'reuse-after-fail-2', keyVersion: 99,
      effectiveSequence: 5, expectedControlRevision: 1,
      publicKeyRaw: new DeviceSigner().publicRaw,
    }),
    'KEY_VERSION_CONFLICT'
  );
  const adj = await adjudicate(h.pool, {
    deviceId: id2, sequence: 2, commandId: 'reuse-after-fail-2',
    expectedConflictRevision: setup2.revision,
    decision: { type: 'select', digest: buildEnvelope(setup2.chain[1]).digest },
  });
  assert.equal(adj.highWatermark, 2);
});

test('concurrent contention across two API instances yields one first result and no partial write', async () => {
  const ROUNDS = 6;
  for (let round = 0; round < ROUNDS; round++) {
    // Independent pools: separate processes would share nothing but the DB.
    const poolA = createPool({ db: { ...h.cfg.db, poolSize: 4 } });
    const poolB = createPool({ db: { ...h.cfg.db, poolSize: 4 } });
    try {
      const devA = `dev-race-a-${round}`;
      const devB = `dev-race-b-${round}`;
      const keyA = new DeviceSigner();
      const keyB = new DeviceSigner();
      await registerDevice(h.pool, { deviceId: devA, publicKeyRaw: keyA.publicRaw });
      await registerDevice(h.pool, { deviceId: devB, publicKeyRaw: keyB.publicRaw });
      const newKeyA = new DeviceSigner();
      const newKeyB = new DeviceSigner();
      const commandId = `race-cmd-${round}`;

      // Different devices => no shared device-row lock; the admin_commands
      // primary key is the only arbitration point.
      const results = await Promise.allSettled([
        rotateKey(poolA, {
          deviceId: devA, commandId, keyVersion: 2, effectiveSequence: 5,
          expectedControlRevision: 1, publicKeyRaw: newKeyA.publicRaw,
        }),
        rotateKey(poolB, {
          deviceId: devB, commandId, keyVersion: 2, effectiveSequence: 5,
          expectedControlRevision: 1, publicKeyRaw: newKeyB.publicRaw,
        }),
      ]);

      const fulfilled = results.filter((r) => r.status === 'fulfilled');
      const rejected = results.filter((r) => r.status === 'rejected');
      assert.equal(fulfilled.length, 1, `round ${round}: expected exactly one success`);
      assert.equal(rejected.length, 1);
      const winner = fulfilled[0].value;
      assert.equal(winner.replayed, false);
      assert.equal(rejected[0].reason.code, 'IDEMPOTENCY_CONFLICT');
      assert.equal(rejected[0].reason.status, 409);
      assert.equal(rejected[0].reason.details.existingKind, 'rotate');

      // Exactly one reservation, holding the winning device's id.
      const { rows: rows1 } = await h.pool.query(
        'SELECT device_id FROM admin_commands WHERE command_id=$1', [commandId]
      );
      assert.equal(rows1.length, 1);
      const winningDevice = rows1[0].device_id;
      assert.ok([devA, devB].includes(winningDevice));
      const losingDevice = winningDevice === devA ? devB : devA;

      // Winner advanced, loser untouched (no partial rotation).
      const winState = await getDevice(h.pool, winningDevice);
      const loseState = await getDevice(h.pool, losingDevice);
      assert.equal(winState.controlRevision, 2);
      assert.equal(winState.keys.length, 2);
      assert.equal(loseState.controlRevision, 1);
      assert.equal(loseState.keys.length, 1);

      // Afterwards the loser deterministically conflicts even against the
      // winner's instance, while replaying the winner returns its first result.
      const replayCmd = {
        deviceId: winningDevice, commandId, keyVersion: 2, effectiveSequence: 5,
        expectedControlRevision: 1,
        publicKeyRaw: winningDevice === devA ? newKeyA.publicRaw : newKeyB.publicRaw,
      };
      const replay = await rotateKey(h.pool, replayCmd);
      assert.equal(replay.replayed, true);
      assert.equal(replay.controlRevision, 2);
      await assertConflict(rotateKey(h.pool, {
        deviceId: losingDevice, commandId, keyVersion: 2, effectiveSequence: 5,
        expectedControlRevision: 1,
        publicKeyRaw: losingDevice === devA ? newKeyA.publicRaw : newKeyB.publicRaw,
      }));

      // Still exactly one reservation after replay + rejected retry.
      const { rows: rows2 } = await h.pool.query(
        'SELECT count(*)::int AS n FROM admin_commands WHERE command_id=$1', [commandId]
      );
      assert.equal(rows2[0].n, 1);
    } finally {
      await poolA.end();
      await poolB.end();
    }
  }
});

test('concurrent contention across different command kinds resolves to one kind', async () => {
  const poolA = createPool({ db: { ...h.cfg.db, poolSize: 4 } });
  const poolB = createPool({ db: { ...h.cfg.db, poolSize: 4 } });
  try {
    // Contender A: rotation on dev-k-a.
    const devRot = 'dev-xk-rot';
    const rotSigner = new DeviceSigner();
    await registerDevice(h.pool, { deviceId: devRot, publicKeyRaw: rotSigner.publicRaw });
    const newKey = new DeviceSigner();

    // Contender B: adjudication on dev-k-b with an open conflict.
    const devAdj = 'dev-xk-adj';
    const setup = await deviceWithOpenConflict(devAdj, 3, 3);

    const commandId = 'cross-kind-race';
    const results = await Promise.allSettled([
      rotateKey(poolA, {
        deviceId: devRot, commandId, keyVersion: 2, effectiveSequence: 7,
        expectedControlRevision: 1, publicKeyRaw: newKey.publicRaw,
      }),
      adjudicate(poolB, {
        deviceId: devAdj, sequence: 3, commandId,
        expectedConflictRevision: setup.revision,
        decision: { type: 'select', digest: buildEnvelope(setup.chain[2]).digest },
      }),
    ]);

    const ok = results.filter((r) => r.status === 'fulfilled');
    const bad = results.filter((r) => r.status === 'rejected');
    assert.equal(ok.length, 1);
    assert.equal(bad.length, 1);
    assert.equal(bad[0].reason.code, 'IDEMPOTENCY_CONFLICT');

    const { rows } = await h.pool.query(
      'SELECT kind, device_id FROM admin_commands WHERE command_id=$1', [commandId]
    );
    assert.equal(rows.length, 1);
    const wonKind = rows[0].kind;
    assert.ok(['rotate', 'adjudicate'].includes(wonKind));

    if (wonKind === 'rotate') {
      assert.equal((await getDevice(h.pool, devRot)).controlRevision, 2);
      assert.equal((await getDevice(h.pool, devAdj)).controlRevision, 1);
      // Loser's conflict is still open and fully adjudicable with a fresh id.
      const c = await getConflict(h.pool, devAdj, 3);
      assert.equal(c.status, 'open');
      const retry = await adjudicate(h.pool, {
        deviceId: devAdj, sequence: 3, commandId: 'fresh-adj-id',
        expectedConflictRevision: c.revision,
        decision: { type: 'select', digest: buildEnvelope(setup.chain[2]).digest },
      });
      assert.equal(retry.highWatermark, 3);
    } else {
      assert.equal((await getDevice(h.pool, devAdj)).highWatermark, 3);
      const rotState = await getDevice(h.pool, devRot);
      assert.equal(rotState.controlRevision, 1);
      assert.equal(rotState.keys.length, 1);
    }
  } finally {
    await poolA.end();
    await poolB.end();
  }
});
