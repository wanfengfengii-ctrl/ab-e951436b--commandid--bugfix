'use strict';
// Global admin commandId semantics.
//
// A commandId is reserved by the FIRST successful admin command across ALL
// kinds (rotate, adjudicate, compact) and ALL devices:
//   * identical kind+content replays the first stored response;
//   * reuse for a different kind or different content is a stable 409
//     IDEMPOTENCY_CONFLICT (never a 500), with no partial writes;
//   * when two API instances (independent pools, no shared memory) contend for
//     one id concurrently, exactly one first result is ever produced and the
//     loser rolls back completely.

import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { setupHarness, stopTestPostgres, truncateAll } from './helpers/harness.mjs';
import { createPool } from '../src/db/pool.mjs';
import { registerDevice, rotateKey, getDevice } from '../src/services/devices.mjs';
import { ingestBatch } from '../src/services/ingest.mjs';
import { adjudicate, getConflict } from '../src/services/conflicts.mjs';
import { compactDevice } from '../src/services/compaction.mjs';
import { DeviceSigner, buildChain, prepareBatch, buildEnvelope } from './helpers/events.mjs';
import { ApiError } from '../src/errors.mjs';

let h;
before(async () => { h = await setupHarness(); });
after(async () => { await h.pool.end(); await stopTestPostgres(); });
beforeEach(async () => { await truncateAll(h.pool); });

const ingest = (pool, deviceId, requestId, events) =>
  ingestBatch(pool, prepareBatch(deviceId, requestId, events));

function makeInstancePool() {
  return createPool({ db: { ...h.cfg.db, poolSize: 4 } });
}

/** Register a device plus a signer. */
async function newDevice(id) {
  const signer = new DeviceSigner();
  await registerDevice(h.pool, { deviceId: id, publicKeyRaw: signer.publicRaw });
  return signer;
}

/** Build an open divergent conflict at the last sequence of a 3-event chain,
 * then promote 1..2, leaving the frontier blocked at the conflict. */
async function blockedDevice(id) {
  const signer = await newDevice(id);
  const chain = buildChain(signer, id, 3);
  const fork = { ...chain[2], payload: { fork: true }, eventId: `fork-3` };
  const { signBytes, encodeB64Url } = await import('../src/crypto/keys.js');
  const { bytes } = buildEnvelope(fork);
  const signedFork = { ...fork, signature: encodeB64Url(signBytes(signer.privateKey, bytes)) };
  const uid = `${id}-${Math.random().toString(36).slice(2)}`;
  await ingest(h.pool, id, `${uid}-fork`, [signedFork]);
  const r = await ingest(h.pool, id, `${uid}-real3`, [chain[2]]);
  assert.equal(r.conflicts[0].reason, 'divergent_candidates');
  await ingest(h.pool, id, `${uid}-12`, [chain[0], chain[1]]);
  const conflict = await getConflict(h.pool, id, 3);
  return { signer, chain, revision: conflict.revision };
}

async function conflictError(p) {
  return p.then(() => null, (e) => e);
}

// --- The exact reported regression ------------------------------------------

test('adjudicate then rotate with the same commandId is a stable 409, not 500, and does not partially rotate', async () => {
  const id = 'dev-crosskind';
  const { chain, revision } = await blockedDevice(id);
  const commandId = 'shared-cmd-' + Math.random().toString(36).slice(2);

  const adj = await adjudicate(h.pool, {
    deviceId: id, sequence: 3, commandId,
    expectedConflictRevision: revision,
    decision: { type: 'select', digest: buildEnvelope(chain[2]).digest },
  });
  assert.equal(adj.highWatermark, 3);

  const k2 = new DeviceSigner();
  const rotate = {
    deviceId: id, commandId, keyVersion: 2, effectiveSequence: 5,
    expectedControlRevision: 1, publicKeyRaw: k2.publicRaw,
  };
  const e1 = await conflictError(rotateKey(h.pool, rotate));
  assert.ok(e1 instanceof ApiError, `expected ApiError, got ${e1}`);
  assert.equal(e1.status, 409);
  assert.equal(e1.code, 'IDEMPOTENCY_CONFLICT');
  assert.equal(e1.details.firstKind, 'adjudicate');
  assert.equal(e1.details.attemptedKind, 'rotate');
  assert.equal(e1.details.commandId, commandId);

  // The conflict is stable on repeat.
  const e2 = await conflictError(rotateKey(h.pool, rotate));
  assert.ok(e2 instanceof ApiError && e2.code === 'IDEMPOTENCY_CONFLICT');

  // No partial rotation: still one key generation, revision 1.
  const state = await getDevice(h.pool, id);
  assert.equal(state.controlRevision, 1);
  assert.equal(state.keys.length, 1);
  assert.equal(state.keys[0].keyVersion, 1);

  // Device versioning still advances normally with a fresh commandId.
  const ok = await rotateKey(h.pool, { ...rotate, commandId: commandId + '-rot' });
  assert.equal(ok.controlRevision, 2);
  assert.equal(ok.replayed, false);
  const after = await getDevice(h.pool, id);
  assert.equal(after.controlRevision, 2);
  assert.equal(after.keys.length, 2);
});

// --- Full cross-kind matrix --------------------------------------------------

test('commandId reuse conflicts in every ordered kind pairing (rotate/adjudicate/compact)', async () => {
  // A device that supports all three command types: resolved conflict +
  // visible prefix long enough to compact.
  const id = 'dev-matrix';
  const { chain, revision } = await blockedDevice(id);

  const adjId = 'm-adj';
  await adjudicate(h.pool, {
    deviceId: id, sequence: 3, commandId: adjId,
    expectedConflictRevision: revision,
    decision: { type: 'select', digest: buildEnvelope(chain[2]).digest },
  });

  const rotId = 'm-rot';
  const k2 = new DeviceSigner();
  await rotateKey(h.pool, {
    deviceId: id, commandId: rotId, keyVersion: 2,
    effectiveSequence: 10, expectedControlRevision: 1, publicKeyRaw: k2.publicRaw,
  });

  const cpId = 'm-cp';
  const cp = await compactDevice(h.pool, h.serverKey, h.cfg, id, 2, cpId);
  assert.equal(cp.checkpoint.sequence, 2);

  const rotCmd = {
    deviceId: id, commandId: 'PLACEHOLDER', keyVersion: 3,
    effectiveSequence: 11, expectedControlRevision: 2,
    publicKeyRaw: new DeviceSigner().publicRaw,
  };
  // adjudicate-shaped reuse (revision 1 conflict already resolved; the global
  // check fires before any conflict/revision lookup).
  const adjCmd = {
    deviceId: id, sequence: 3, commandId: 'PLACEHOLDER',
    expectedConflictRevision: revision,
    decision: { type: 'select', digest: buildEnvelope(chain[2]).digest },
  };
  const compact = (cid) =>
    conflictError(compactDevice(h.pool, h.serverKey, h.cfg, id, 3, cid));

  const pairs = [
    // adjudicate id reused by ...
    ['rotate after adjudicate', () => conflictError(rotateKey(h.pool, { ...rotCmd, commandId: adjId })), 'adjudicate'],
    ['compact after adjudicate', () => compact(adjId), 'adjudicate'],
    // rotate id reused by ...
    ['adjudicate after rotate', () => conflictError(adjudicate(h.pool, { ...adjCmd, commandId: rotId })), 'rotate'],
    ['compact after rotate', () => compact(rotId), 'rotate'],
    // compact id reused by ...
    ['rotate after compact', () => conflictError(rotateKey(h.pool, { ...rotCmd, commandId: cpId })), 'compact'],
    ['adjudicate after compact', () => conflictError(adjudicate(h.pool, { ...adjCmd, commandId: cpId })), 'compact'],
  ];

  for (const [name, run, firstKind] of pairs) {
    const e = await run();
    assert.ok(e instanceof ApiError, `${name}: expected ApiError`);
    assert.equal(e.code, 'IDEMPOTENCY_CONFLICT', name);
    assert.equal(e.status, 409, name);
    assert.equal(e.details.firstKind, firstKind, name);
  }

  // Exactly the three first outcomes are stored, each owning its id.
  const { rows } = await h.pool.query(
    `SELECT command_id, kind FROM admin_commands WHERE device_id=$1 ORDER BY command_id`,
    [id]
  );
  assert.deepEqual(rows.map((r) => [r.command_id, r.kind]).sort(), [
    [adjId, 'adjudicate'], [cpId, 'compact'], [rotId, 'rotate'],
  ]);
});

test('cross-device reuse of one commandId also conflicts', async () => {
  const a = await newDevice('dev-xd-a');
  const b = await newDevice('dev-xd-b');
  const commandId = 'cross-device-cmd';

  await rotateKey(h.pool, {
    deviceId: 'dev-xd-a', commandId, keyVersion: 2, effectiveSequence: 5,
    expectedControlRevision: 1, publicKeyRaw: new DeviceSigner().publicRaw,
  });

  const e = await conflictError(rotateKey(h.pool, {
    deviceId: 'dev-xd-b', commandId, keyVersion: 2, effectiveSequence: 5,
    expectedControlRevision: 1, publicKeyRaw: new DeviceSigner().publicRaw,
  }));
  assert.ok(e instanceof ApiError && e.code === 'IDEMPOTENCY_CONFLICT');
  assert.equal(e.details.firstDeviceId, 'dev-xd-a');

  // The second device was never modified.
  const stateB = await getDevice(h.pool, 'dev-xd-b');
  assert.equal(stateB.controlRevision, 1);
  assert.equal(stateB.keys.length, 1);
  void a;
});

// --- Multi-instance concurrency ----------------------------------------------

test('two instances: cross-device contention for one id yields exactly one first result; loser has no partial rotation', async () => {
  const ROUNDS = 10;
  const poolA = makeInstancePool();
  const poolB = makeInstancePool();
  for (let round = 0; round < ROUNDS; round++) {
    const idA = `dev-race-a-${round}`;
    const idB = `dev-race-b-${round}`;
    await newDevice(idA);
    await newDevice(idB);
    const commandId = `race-cmd-${round}-` + Math.random().toString(36).slice(2);

    const mk = (id, pool) => rotateKey(pool, {
      deviceId: id, commandId, keyVersion: 2, effectiveSequence: 9,
      expectedControlRevision: 1, publicKeyRaw: new DeviceSigner().publicRaw,
    });

    const [ra, rb] = await Promise.allSettled([mk(idA, poolA), mk(idB, poolB)]);
    const outcomes = [[idA, ra], [idB, rb]];
    const fulfilled = outcomes.filter(([, r]) => r.status === 'fulfilled');
    const rejected = outcomes.filter(([, r]) => r.status === 'rejected');
    assert.equal(fulfilled.length, 1, `round ${round}: exactly one winner`);
    assert.equal(rejected.length, 1, `round ${round}: exactly one loser`);
    const loserErr = rejected[0][1].reason;
    assert.ok(
      loserErr instanceof ApiError && loserErr.status === 409 && loserErr.code === 'IDEMPOTENCY_CONFLICT',
      `round ${round}: loser got a stable 409`
    );
    assert.equal(fulfilled[0][1].value.replayed, false);

    // The loser request stays a stable conflict.
    const loserDevice = rejected[0][0];
    const again = await conflictError(rotateKey(h.pool, {
      deviceId: loserDevice, commandId, keyVersion: 2, effectiveSequence: 9,
      expectedControlRevision: 1, publicKeyRaw: new DeviceSigner().publicRaw,
    }));
    assert.ok(again instanceof ApiError && again.code === 'IDEMPOTENCY_CONFLICT');

    for (const id of [idA, idB]) {
      const state = await getDevice(h.pool, id);
      const isWinner = id === fulfilled[0][0];
      assert.equal(state.controlRevision, isWinner ? 2 : 1, `round ${round} ${id} revision`);
      assert.equal(state.keys.length, isWinner ? 2 : 1, `round ${round} ${id} key count`);
    }
    const { rows } = await h.pool.query(
      'SELECT count(*)::int AS n FROM admin_commands WHERE command_id=$1',
      [commandId]
    );
    assert.equal(rows[0].n, 1, `round ${round}: one stored outcome`);
  }
  await poolA.end();
  await poolB.end();
});

test('two instances: same-device identical concurrent rotates collapse to one outcome', async () => {
  await newDevice('dev-race-same');
  const poolA = makeInstancePool();
  const poolB = makeInstancePool();
  const commandId = 'same-rot-cmd';
  const key = new DeviceSigner();
  const cmd = {
    deviceId: 'dev-race-same', commandId, keyVersion: 2, effectiveSequence: 6,
    expectedControlRevision: 1, publicKeyRaw: key.publicRaw,
  };

  const [ra, rb] = await Promise.allSettled([
    rotateKey(poolA, cmd),
    rotateKey(poolB, cmd),
  ]);
  assert.equal(ra.status, 'fulfilled');
  assert.equal(rb.status, 'fulfilled');
  const flags = [ra.value.replayed, rb.value.replayed].sort();
  assert.deepEqual(flags, [false, true]);

  const state = await getDevice(h.pool, 'dev-race-same');
  assert.equal(state.controlRevision, 2);
  assert.equal(state.keys.length, 2);

  await poolA.end();
  await poolB.end();
});

test('two instances: cross-device adjudicate contention leaves the loser conflict open and candidates staged', async () => {
  // Two devices, each with an open conflict at seq 3.
  const setup = {};
  for (const id of ['dev-adj-a', 'dev-adj-b']) {
    setup[id] = await blockedDevice(id);
  }
  const poolA = makeInstancePool();
  const poolB = makeInstancePool();
  const commandId = 'adj-race-' + Math.random().toString(36).slice(2);

  const mk = (id, pool) => adjudicate(pool, {
    deviceId: id, sequence: 3, commandId,
    expectedConflictRevision: setup[id].revision,
    decision: { type: 'select', digest: buildEnvelope(setup[id].chain[2]).digest },
  });

  const [ra, rb] = await Promise.allSettled([
    mk('dev-adj-a', poolA),
    mk('dev-adj-b', poolB),
  ]);
  const outcomes = [['dev-adj-a', ra], ['dev-adj-b', rb]];
  const fulfilled = outcomes.filter(([, r]) => r.status === 'fulfilled');
  const rejected = outcomes.filter(([, r]) => r.status === 'rejected');
  assert.equal(fulfilled.length, 1);
  assert.equal(rejected.length, 1);
  assert.equal(rejected[0][1].reason.code, 'IDEMPOTENCY_CONFLICT');
  assert.equal(fulfilled[0][1].value.highWatermark, 3);

  // Loser: conflict still open at the same revision, no candidate rejected.
  const loser = rejected[0][0];
  const c = await getConflict(h.pool, loser, 3);
  assert.equal(c.status, 'open');
  assert.equal(c.revision, setup[loser].revision);
  const { rows } = await h.pool.query(
    `SELECT count(*)::int AS n FROM event_records
      WHERE device_id=$1 AND sequence=3 AND status='rejected'`,
    [loser]
  );
  assert.equal(rows[0].n, 0);

  // Winner: resolved.
  const winner = fulfilled[0][0];
  const cw = await getConflict(h.pool, winner, 3);
  assert.equal(cw.status, 'resolved');

  await poolA.end();
  await poolB.end();
});

test('two instances: a rotate and an adjudicate racing on one id across devices cannot both succeed', async () => {
  // Device A supports an adjudicate (open conflict); device B supports a rotate.
  const aSetup = await blockedDevice('dev-mix-a');
  await newDevice('dev-mix-b');
  const poolA = makeInstancePool();
  const poolB = makeInstancePool();
  const commandId = 'mix-race-' + Math.random().toString(36).slice(2);

  const adjCall = adjudicate(poolA, {
    deviceId: 'dev-mix-a', sequence: 3, commandId,
    expectedConflictRevision: aSetup.revision,
    decision: { type: 'select', digest: buildEnvelope(aSetup.chain[2]).digest },
  });
  const rotCall = rotateKey(poolB, {
    deviceId: 'dev-mix-b', commandId, keyVersion: 2, effectiveSequence: 4,
    expectedControlRevision: 1, publicKeyRaw: new DeviceSigner().publicRaw,
  });

  const [adjRes, rotRes] = await Promise.allSettled([adjCall, rotCall]);
  const winnerCount = [adjRes, rotRes].filter((r) => r.status === 'fulfilled').length;
  assert.equal(winnerCount, 1);
  for (const r of [adjRes, rotRes]) {
    if (r.status === 'rejected') {
      assert.ok(r.reason instanceof ApiError && r.reason.code === 'IDEMPOTENCY_CONFLICT');
    }
  }

  // Cross-check final state matches which call won.
  const confA = await getConflict(h.pool, 'dev-mix-a', 3);
  const stateB = await getDevice(h.pool, 'dev-mix-b');
  if (adjRes.status === 'fulfilled') {
    assert.equal(confA.status, 'resolved');
    assert.equal(stateB.keys.length, 1);
  } else {
    assert.equal(confA.status, 'open');
    assert.equal(stateB.keys.length, 2);
  }

  await poolA.end();
  await poolB.end();
});

// --- Existing behavior still holds under global reservation ------------------

test('identical adjudication replay returns the first stored response after global reservation', async () => {
  const id = 'dev-replay-global';
  const { chain, revision } = await blockedDevice(id);
  const commandId = 'replay-adj-cmd';
  const cmd = {
    deviceId: id, sequence: 3, commandId,
    expectedConflictRevision: revision,
    decision: { type: 'select', digest: buildEnvelope(chain[2]).digest },
  };
  const first = await adjudicate(h.pool, cmd);
  assert.equal(first.replayed, false);
  const again = await adjudicate(h.pool, cmd);
  assert.equal(again.replayed, true);
  assert.equal(again.highWatermark, 3);
  assert.equal(again.resolution, 'selected');
});
