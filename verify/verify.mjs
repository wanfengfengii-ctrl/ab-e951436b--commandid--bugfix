'use strict';
// One-shot acceptance service for `docker compose run --rm verify`.
//
// It exercises the ENTIRE deployed topology over HTTP through the proxy:
// both API instances (asserted via x-instance), the database as the shared
// arbiter, and the background worker. It needs no external network: only
// Node's built-in fetch/crypto and the service's own deterministic modules.
// Exits 0 only if every requirement-level scenario passes.

import { createPrivateKey, createPublicKey } from 'node:crypto';
import { generateSigningKey, signBytes, publicKeyToRaw, encodeB64Url, decodeB64Url } from '../src/crypto/keys.js';
import { buildEnvelope } from '../src/crypto/envelope.js';
import { canonicalCheckpoint } from '../src/crypto/checkpoint.mjs';
import { verifyBytes } from '../src/crypto/keys.js';

const BASE = process.env.BASE_URL || 'http://proxy';
const ADMIN = process.env.ADMIN_TOKEN || 'acceptance-admin-token';
const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

let passed = 0;
const failures = [];
function check(name, cond, detail = '') {
  if (cond) {
    passed++;
    console.log(`  ok - ${name}`);
  } else {
    failures.push(`${name} ${detail}`);
    console.log(`  FAIL - ${name} ${detail}`);
  }
}
async function group(name, fn) {
  console.log(`\n* ${name}`);
  try {
    await fn();
  } catch (e) {
    check(name, false, `threw: ${e.stack || e.message}`);
  }
}

async function api(method, path, { body, admin, raw, contentType } = {}) {
  const headers = {};
  if (body !== undefined || raw !== undefined) headers['content-type'] = contentType || 'application/json';
  if (admin) headers['x-admin-token'] = ADMIN;
  const res = await fetch(BASE + path, {
    method,
    headers,
    body: raw ?? (body !== undefined ? JSON.stringify(body) : undefined),
  });
  let json = null;
  try { json = await res.json(); } catch { /* non-json */ }
  return { status: res.status, json, headers: res.headers, instance: res.headers.get('x-instance') };
}

class Signer {
  constructor() {
    const kp = generateSigningKey();
    this.privateKey = kp.privateKey;
    this.publicRaw = publicKeyToRaw(kp.publicKey);
    this.publicB64Url = encodeB64Url(this.publicRaw);
  }
  event(fields) {
    const { bytes, digest } = buildEnvelope(fields);
    return { event: { ...fields, signature: encodeB64Url(signBytes(this.privateKey, bytes)) }, digest, bytes };
  }
}

function chain(signer, deviceId, n, { keyVersion = 1, startSeq = 1, prev = '0'.repeat(64), timeBase = 0 } = {}) {
  const out = [];
  let prevDigest = prev;
  for (let i = 0; i < n; i++) {
    const seq = startSeq + i;
    const { event, digest } = signer.event({
      deviceId, sequence: seq, eventId: `evt-${seq}-${timeBase}`,
      occurredAt: `2026-01-01T00:${String(i % 60).padStart(2, '0')}:00Z`,
      keyVersion, prevDigest, payload: { i, run: timeBase },
    });
    out.push({ event, digest });
    prevDigest = digest;
  }
  return out;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const rid = (() => { let n = 0; const p = 'v-' + Math.random().toString(36).slice(2, 8) + '-'; return () => p + (n++); })();

async function main() {
  console.log(`Acceptance target: ${BASE}`);

  await group('health and topology', async () => {
    const h = await api('GET', '/healthz');
    check('liveness 200', h.status === 200);
    const r = await api('GET', '/healthz/ready');
    check('readiness queries the database', r.status === 200);
    // Round-robin must spread load across both deployed API instances.
    const seen = new Set();
    for (let i = 0; i < 8; i++) seen.add((await api('GET', '/healthz')).instance);
    check('both API instances observed behind proxy', seen.size >= 2, `seen=[${[...seen].join(',')}]`);
  });

  const deviceId = 'acc-' + Math.random().toString(36).slice(2, 10);
  const signer = new Signer();

  await group('registration', async () => {
    const reg = await api('POST', '/v1/devices', { body: { deviceId, publicKey: signer.publicB64Url } });
    check('register 201 with keyVersion 1', reg.status === 201 && reg.json.keyVersion === 1);
    const dup = await api('POST', '/v1/devices', { body: { deviceId, publicKey: signer.publicB64Url } });
    check('identical re-registration is idempotent', dup.status === 200);
  });

  await group('out-of-order batch ingestion and fixed-view reads', async () => {
    const c = chain(signer, deviceId, 6);
    const ingest = async (events) => api('POST', `/v1/devices/${deviceId}/ingest`, { body: { requestId: rid(), events: events.map((x) => x.event) } });

    let r = await ingest([c[2], c[3]]);
    check('future events staged, hwm stays 0', r.status === 200 && r.json.highWatermark === 0);
    r = await ingest([c[0]]);
    check('seq1 promotes to 1', r.json.highWatermark === 1);
    r = await ingest([c[1]]);
    check('filling seq2 promotes whole staged run to 4', r.json.highWatermark === 4);
    r = await ingest([c[4], c[5]]);
    check('tail promotes to 6', r.json.highWatermark === 6);

    const p1 = await api('GET', `/v1/devices/${deviceId}/events?limit=2`);
    check('first page fixed view returns hwm + cursor', p1.json.viewHighWatermark === 6 && p1.json.events.length === 2 && !!p1.json.nextCursor);
    const viewId = p1.json.viewId;
    const p2 = await api('GET', `/v1/devices/${deviceId}/events?limit=2&cursor=${encodeURIComponent(p1.json.nextCursor)}`);
    check('cursor continues inside same view', p2.json.viewId === viewId && p2.json.events.map((e) => e.sequence).join() === '3,4');

    const badCursor = p1.json.nextCursor.replace(/^./, (x) => (x === 'A' ? 'B' : 'A'));
    const tampered = await api('GET', `/v1/devices/${deviceId}/events?cursor=${encodeURIComponent(badCursor)}`);
    check('tampered cursor rejected', tampered.status === 400);
  });

  await group('idempotency', async () => {
    // A fresh device for clean sequence ids.
    const d2 = 'acc-idem-' + Math.random().toString(36).slice(2, 8);
    const cc = chain(signer, d2, 1);
    const body = { requestId: 'idem-' + rid(), events: [cc[0].event] };
    await api('POST', '/v1/devices', { body: { deviceId: d2, publicKey: signer.publicB64Url } });
    const a = await api('POST', `/v1/devices/${d2}/ingest`, { body });
    const b = await api('POST', `/v1/devices/${d2}/ingest`, { body });
    check('identical retry replays first result', a.status === 200 && b.json.replayed === true);
    // Same requestId, genuinely different (re-signed) canonical content.
    const fork = signer.event({ ...cc[0].event, payload: { changed: true } });
    const divergent = { requestId: body.requestId, events: [fork.event] };
    const cfl = await api('POST', `/v1/devices/${d2}/ingest`, { body: divergent });
    check('same requestId different content => stable 409', cfl.status === 409 && cfl.json.error.code === 'IDEMPOTENCY_CONFLICT');
    const cflAgain = await api('POST', `/v1/devices/${d2}/ingest`, { body: divergent });
    check('the conflict is stable on repeat', cflAgain.status === 409);
  });

  await group('atomic failure and admin auth', async () => {
    const d3 = 'acc-atom-' + Math.random().toString(36).slice(2, 8);
    await api('POST', '/v1/devices', { body: { deviceId: d3, publicKey: signer.publicB64Url } });
    const c = chain(signer, d3, 3);
    const bad = { ...c[2].event, signature: c[0].event.signature };
    const r = await api('POST', `/v1/devices/${d3}/ingest`, { body: { requestId: rid(), events: [c[0].event, c[1].event, bad] } });
    check('one bad signature rejects whole batch', r.status === 422 && r.json.error.code === 'SIGNATURE_INVALID');
    const state = await api('GET', `/v1/devices/${d3}`);
    check('no partial data after failed batch', state.json.highWatermark === 0);
    const noAuth = await api('POST', `/v1/devices/${d3}/keys/rotate`, {
      body: { deviceId: d3, commandId: rid(), keyVersion: 2, effectiveSequence: 50, expectedControlRevision: 1, publicKey: new Signer().publicB64Url },
    });
    check('rotation without admin credential is 401', noAuth.status === 401);
  });

  await group('key rotation generation boundary', async () => {
    const d4 = 'acc-rot-' + Math.random().toString(36).slice(2, 8);
    const k1 = new Signer();
    const k2 = new Signer();
    await api('POST', '/v1/devices', { body: { deviceId: d4, publicKey: k1.publicB64Url } });
    const rot = await api('POST', `/v1/devices/${d4}/keys/rotate`, {
      admin: true,
      body: { deviceId: d4, commandId: rid(), keyVersion: 2, effectiveSequence: 5, expectedControlRevision: 1, publicKey: k2.publicB64Url },
    });
    check('rotation accepted at rev 2', rot.status === 200 && rot.json.controlRevision === 2);

    const oldPart = chain(k1, d4, 4, { keyVersion: 1 });
    await api('POST', `/v1/devices/${d4}/ingest`, { body: { requestId: rid(), events: oldPart.map((x) => x.event) } });
    const e5 = k2.event({
      deviceId: d4, sequence: 5, eventId: 'e5', occurredAt: '2026-02-01T00:00:00Z',
      keyVersion: 2, prevDigest: oldPart[3].digest, payload: { gen: 2 },
    });
    const after = await api('POST', `/v1/devices/${d4}/ingest`, { body: { requestId: rid(), events: [e5.event] } });
    check('old backfill + new boundary event both promote to 5', after.json.highWatermark === 5);

    const oldAtBoundary = k1.event({
      deviceId: d4, sequence: 6, eventId: 'e6', occurredAt: '2026-02-01T00:00:01Z',
      keyVersion: 1, prevDigest: e5.digest, payload: {},
    });
    const rejected = await api('POST', `/v1/devices/${d4}/ingest`, { body: { requestId: rid(), events: [oldAtBoundary.event] } });
    check('old key past boundary rejected atomically', rejected.status === 422 && rejected.json.error.code === 'KEY_GENERATION_MISMATCH');
  });

  await group('conflict adjudication (divergent, reject_all, bad predecessor)', async () => {
    const d5 = 'acc-conf-' + Math.random().toString(36).slice(2, 8);
    const s = new Signer();
    await api('POST', '/v1/devices', { body: { deviceId: d5, publicKey: s.publicB64Url } });
    const c = chain(s, d5, 3);

    // Two different seq-3 candidates while frontier is at 0: divergent conflict.
    const fork3 = s.event({ ...c[2].event, payload: { fork: true } });
    await api('POST', `/v1/devices/${d5}/ingest`, { body: { requestId: rid(), events: [fork3.event] } });
    const pre = await api('POST', `/v1/devices/${d5}/ingest`, { body: { requestId: rid(), events: [c[2].event] } });
    check('divergent conflict opened at seq 3', pre.json.conflicts?.[0]?.reason === 'divergent_candidates');
    const revision = pre.json.conflicts[0].revision;

    await api('POST', `/v1/devices/${d5}/ingest`, { body: { requestId: rid(), events: [c[0].event, c[1].event] } });
    let st = await api('GET', `/v1/devices/${d5}`);
    check('watermark stops at previous sequence (2)', st.json.highWatermark === 2);

    const stale = await api('POST', `/v1/devices/${d5}/conflicts/3/adjudicate`, {
      admin: true,
      body: { deviceId: d5, sequence: 3, commandId: rid(), expectedConflictRevision: revision + 5, decision: { type: 'select', digest: c[2].digest } },
    });
    check('stale revision rejected', stale.status === 409 && stale.json.error.code === 'CONFLICT_REVISION_MISMATCH');

    const adj = await api('POST', `/v1/devices/${d5}/conflicts/3/adjudicate`, {
      admin: true,
      body: { deviceId: d5, sequence: 3, commandId: 'cmd-' + rid(), expectedConflictRevision: revision, decision: { type: 'select', digest: c[2].digest } },
    });
    check('adjudication promotes run through 3', adj.status === 200 && adj.json.highWatermark === 3);
    const page = await api('GET', `/v1/devices/${d5}/events?limit=10`);
    check('visible seq3 is the selected candidate', page.json.events[2].payload.fork === undefined);

    // bad predecessor on a fresh device: reject_all then re-upload.
    const d6 = 'acc-bp-' + Math.random().toString(36).slice(2, 8);
    const s6 = new Signer();
    await api('POST', '/v1/devices', { body: { deviceId: d6, publicKey: s6.publicB64Url } });
    const c6 = chain(s6, d6, 2);
    const bad2 = s6.event({ ...c6[1].event, prevDigest: 'a'.repeat(64) });
    await api('POST', `/v1/devices/${d6}/ingest`, { body: { requestId: rid(), events: [c6[0].event] } });
    const bpr = await api('POST', `/v1/devices/${d6}/ingest`, { body: { requestId: rid(), events: [bad2.event] } });
    check('bad_predecessor conflict recorded', bpr.json.conflicts?.[0]?.reason === 'bad_predecessor');
    const cfl = await api('GET', `/v1/devices/${d6}/conflicts/2`);
    const rej = await api('POST', `/v1/devices/${d6}/conflicts/2/adjudicate`, {
      admin: true,
      body: { deviceId: d6, sequence: 2, commandId: rid(), expectedConflictRevision: cfl.json.revision, decision: { type: 'reject_all' } },
    });
    check('reject_all resolves without advancing', rej.status === 200 && rej.json.highWatermark === 1);
    const reup = await api('POST', `/v1/devices/${d6}/ingest`, { body: { requestId: rid(), events: [c6[1].event] } });
    check('re-upload revives and promotes to 2', reup.json.highWatermark === 2 && reup.json.conflicts.length === 0);
  });

  await group('global admin commandId idempotency across command types', async () => {
    // The reported defect: a commandId that successfully adjudicated a
    // conflict was later accepted for a different command type and died with
    // HTTP 500 on the primary-key collision. It must now be a stable 409.
    const da = 'acc-gid-' + Math.random().toString(36).slice(2, 8);
    const sa = new Signer();
    await api('POST', '/v1/devices', { body: { deviceId: da, publicKey: sa.publicB64Url } });
    const ca = chain(sa, da, 2);
    const fork2 = sa.event({ ...ca[1].event, payload: { fork: true } });
    await api('POST', `/v1/devices/${da}/ingest`, { body: { requestId: rid(), events: [fork2.event] } });
    const preA = await api('POST', `/v1/devices/${da}/ingest`, { body: { requestId: rid(), events: [ca[1].event] } });
    check('divergent conflict opened for global-id scenario', preA.json.conflicts?.[0]?.reason === 'divergent_candidates');
    await api('POST', `/v1/devices/${da}/ingest`, { body: { requestId: rid(), events: [ca[0].event] } });
    const revA = preA.json.conflicts[0].revision;

    const gidAdj = 'g-adj-' + rid();
    const adjBody = {
      deviceId: da, sequence: 2, commandId: gidAdj, expectedConflictRevision: revA,
      decision: { type: 'select', digest: ca[1].digest },
    };
    const adj1 = await api('POST', `/v1/devices/${da}/conflicts/2/adjudicate`, { admin: true, body: adjBody });
    check('first adjudication succeeds (200)', adj1.status === 200 && adj1.json.highWatermark === 2);
    const adjReplay = await api('POST', `/v1/devices/${da}/conflicts/2/adjudicate`, { admin: true, body: adjBody });
    check('identical adjudication replays first result', adjReplay.status === 200 && adjReplay.json.replayed === true);

    // Reuse the SAME commandId for a rotation with different type/content.
    const rotOnAdjId = {
      deviceId: da, commandId: gidAdj, keyVersion: 2, effectiveSequence: 5,
      expectedControlRevision: 1, publicKey: new Signer().publicB64Url,
    };
    const cross1 = await api('POST', `/v1/devices/${da}/keys/rotate`, { admin: true, body: rotOnAdjId });
    check(
      'adjudicate id reused for rotation => structured 409 (not 500)',
      cross1.status === 409 &&
        cross1.json.error.code === 'IDEMPOTENCY_CONFLICT' &&
        cross1.json.error.details?.existingKind === 'adjudicate' &&
        cross1.json.error.details?.requestedKind === 'rotate' &&
        cross1.json.error.details?.existingDeviceId === da,
      `status=${cross1.status} code=${cross1.json?.error?.code}`
    );
    const cross1again = await api('POST', `/v1/devices/${da}/keys/rotate`, { admin: true, body: rotOnAdjId });
    check('cross-kind conflict is stable on repeat', cross1again.status === 409);
    // ...and a third command type on the same id conflicts the same way.
    const crossCompact = await api('POST', '/v1/admin/compact', {
      admin: true, body: { deviceId: da, commandId: gidAdj, cutoffSequence: 1 },
    });
    check('adjudicate id reused for compaction => 409', crossCompact.status === 409 && crossCompact.json.error.details?.existingKind === 'adjudicate');

    // No partial rotation: the rejected rotation changed nothing.
    let stA = await api('GET', `/v1/devices/${da}`);
    check('rejected cross-kind reuse left no partial rotation',
      stA.json.controlRevision === 1 && stA.json.keys.length === 1);

    // rotate -> adjudicate/compact reuse.
    const gidRot = 'g-rot-' + rid();
    const rotBody = {
      deviceId: da, commandId: gidRot, keyVersion: 2, effectiveSequence: 5,
      expectedControlRevision: 1, publicKey: new Signer().publicB64Url,
    };
    const rot1 = await api('POST', `/v1/devices/${da}/keys/rotate`, { admin: true, body: rotBody });
    check('rotation succeeds on a fresh global id', rot1.status === 200 && rot1.json.controlRevision === 2);
    const rotReplay = await api('POST', `/v1/devices/${da}/keys/rotate`, { admin: true, body: rotBody });
    check('identical rotation replays first result', rotReplay.status === 200 && rotReplay.json.replayed === true);

    // An otherwise-legal adjudication on a second device carrying the rotate id.
    const db = 'acc-gid2-' + Math.random().toString(36).slice(2, 8);
    const sb = new Signer();
    await api('POST', '/v1/devices', { body: { deviceId: db, publicKey: sb.publicB64Url } });
    const cb = chain(sb, db, 1);
    await api('POST', `/v1/devices/${db}/ingest`, { body: { requestId: rid(), events: [cb[0].event] } });
    const other1 = sb.event({ ...cb[0].event, payload: { divergent: true } });
    const pv = await api('POST', `/v1/devices/${db}/ingest`, { body: { requestId: rid(), events: [other1.event] } });
    check('post-visibility divergence opened on second device', pv.json.conflicts?.[0]?.reason === 'post_visibility_divergence');
    const adjOnRotId = await api('POST', `/v1/devices/${db}/conflicts/1/adjudicate`, {
      admin: true,
      body: { deviceId: db, sequence: 1, commandId: gidRot, expectedConflictRevision: pv.json.conflicts[0].revision, decision: { type: 'select', digest: cb[0].digest } },
    });
    check('rotate id reused for adjudication => 409',
      adjOnRotId.status === 409 && adjOnRotId.json.error.details?.existingKind === 'rotate');

    // compact -> rotate reuse.
    const gidCp = 'g-cp-' + rid();
    const cp1 = await api('POST', '/v1/admin/compact', {
      admin: true, body: { deviceId: da, commandId: gidCp, cutoffSequence: 1 },
    });
    check('manual compaction succeeds on a fresh global id', cp1.status === 200 && cp1.json.checkpoint.sequence === 1);
    const cpReplay = await api('POST', '/v1/admin/compact', {
      admin: true, body: { deviceId: da, commandId: gidCp, cutoffSequence: 1 },
    });
    check('identical compaction replays first result', cpReplay.status === 200 && cpReplay.json.replayed === true);
    const rotOnCpId = await api('POST', `/v1/devices/${da}/keys/rotate`, {
      admin: true,
      body: { deviceId: da, commandId: gidCp, keyVersion: 3, effectiveSequence: 9, expectedControlRevision: 2, publicKey: new Signer().publicB64Url },
    });
    check('compact id reused for rotation => 409', rotOnCpId.status === 409 && rotOnCpId.json.error.details?.existingKind === 'compact');

    // Device version bookkeeping only advanced via genuinely new commands.
    stA = await api('GET', `/v1/devices/${da}`);
    check('device version advanced exactly once across the scenario',
      stA.json.controlRevision === 2 && stA.json.keys.length === 2);
    const stB = await api('GET', `/v1/devices/${db}`);
    const confB = await api('GET', `/v1/devices/${db}/conflicts/1`);
    check('second device was never adjudicated by the rejected reuse',
      stB.json.controlRevision === 1 && confB.json.status === 'open'
        && confB.json.reason === 'post_visibility_divergence'
        && confB.json.decidedCommandId === null);
  });

  await group('concurrent admin commandId contention across API instances', async () => {
    // Two requests with one commandId fired together; round-robin spreads them
    // over both API instances, and the database is the sole arbiter.
    const dc = 'acc-gc1-' + Math.random().toString(36).slice(2, 8);
    const dd = 'acc-gc2-' + Math.random().toString(36).slice(2, 8);
    const sc = new Signer();
    const sd = new Signer();
    await api('POST', '/v1/devices', { body: { deviceId: dc, publicKey: sc.publicB64Url } });
    await api('POST', '/v1/devices', { body: { deviceId: dd, publicKey: sd.publicB64Url } });
    const shared = 'g-conc-' + rid();
    const mkRot = (deviceId) => ({
      deviceId, commandId: shared, keyVersion: 2, effectiveSequence: 5,
      expectedControlRevision: 1, publicKey: new Signer().publicB64Url,
    });
    const [ra, rb] = await Promise.all([
      api('POST', `/v1/devices/${dc}/keys/rotate`, { admin: true, body: mkRot(dc) }),
      api('POST', `/v1/devices/${dd}/keys/rotate`, { admin: true, body: mkRot(dd) }),
    ]);
    const statuses = [ra.status, rb.status].sort();
    check('exactly one concurrent contender gets the first result', statuses.join() === '200,409',
      `statuses=${statuses.join()}`);
    const loser = ra.status === 409 ? ra : rb;
    check('loser receives structured idempotency conflict',
      loser.json.error.code === 'IDEMPOTENCY_CONFLICT' && loser.json.error.details?.existingKind === 'rotate');
    const [stC, stD] = await Promise.all([
      api('GET', `/v1/devices/${dc}`),
      api('GET', `/v1/devices/${dd}`),
    ]);
    const winners = [stC, stD].filter((s) => s.json.controlRevision === 2);
    const losers = [stC, stD].filter((s) => s.json.controlRevision === 1);
    check('one device rotated, the loser has no partial write',
      winners.length === 1 && losers.length === 1 && losers[0].json.keys.length === 1);
    const winningDevice = winners[0].json.deviceId;
    // Replaying the winning content returns the stored first result forever.
    const winBody = {
      deviceId: winningDevice, commandId: shared, keyVersion: 2, effectiveSequence: 5,
      expectedControlRevision: 1,
      publicKey: winners[0].json.keys[1].publicKey,
    };
    const replay = await api('POST', `/v1/devices/${winningDevice}/keys/rotate`, { admin: true, body: winBody });
    check('winner content replays after the race', replay.status === 200 && replay.json.replayed === true);

    // Cross-kind concurrent contention: rotate vs adjudicate on different
    // devices, one commandId, fired simultaneously.
    const de = 'acc-gx1-' + Math.random().toString(36).slice(2, 8);
    const df = 'acc-gx2-' + Math.random().toString(36).slice(2, 8);
    const se = new Signer();
    const sf = new Signer();
    await api('POST', '/v1/devices', { body: { deviceId: de, publicKey: se.publicB64Url } });
    await api('POST', '/v1/devices', { body: { deviceId: df, publicKey: sf.publicB64Url } });
    const cf = chain(sf, df, 2);
    const forkF = sf.event({ ...cf[1].event, payload: { fork: true } });
    await api('POST', `/v1/devices/${df}/ingest`, { body: { requestId: rid(), events: [forkF.event] } });
    const preF = await api('POST', `/v1/devices/${df}/ingest`, { body: { requestId: rid(), events: [cf[1].event] } });
    await api('POST', `/v1/devices/${df}/ingest`, { body: { requestId: rid(), events: [cf[0].event] } });
    const sharedX = 'g-xconc-' + rid();
    const [xr, xa] = await Promise.all([
      api('POST', `/v1/devices/${de}/keys/rotate`, {
        admin: true,
        body: { deviceId: de, commandId: sharedX, keyVersion: 2, effectiveSequence: 7, expectedControlRevision: 1, publicKey: new Signer().publicB64Url },
      }),
      api('POST', `/v1/devices/${df}/conflicts/2/adjudicate`, {
        admin: true,
        body: { deviceId: df, sequence: 2, commandId: sharedX, expectedConflictRevision: preF.json.conflicts[0].revision, decision: { type: 'select', digest: cf[1].digest } },
      }),
    ]);
    const xstatuses = [xr.status, xa.status].sort();
    check('cross-kind race also yields exactly one 200 and one 409', xstatuses.join() === '200,409',
      `statuses=${xstatuses.join()}`);

    const [stE, stF, confF] = await Promise.all([
      api('GET', `/v1/devices/${de}`),
      api('GET', `/v1/devices/${df}`),
      api('GET', `/v1/devices/${df}/conflicts/2`),
    ]);
    if (xr.status === 200) {
      check('rotation winner advanced; adjudication loser left conflict open',
        stE.json.controlRevision === 2 && stF.json.highWatermark === 1 && confF.json.status === 'open');
      // The loser can still complete its work on a fresh id: no poisoning.
      const retry = await api('POST', `/v1/devices/${df}/conflicts/2/adjudicate`, {
        admin: true,
        body: { deviceId: df, sequence: 2, commandId: rid(), expectedConflictRevision: confF.json.revision, decision: { type: 'select', digest: cf[1].digest } },
      });
      check('adjudication loser succeeds on a fresh commandId', retry.status === 200 && retry.json.highWatermark === 2);
    } else {
      check('adjudication winner advanced; rotation loser has no partial key',
        stF.json.highWatermark === 2 && stE.json.controlRevision === 1 && stE.json.keys.length === 1);
      const retry = await api('POST', `/v1/devices/${de}/keys/rotate`, {
        admin: true,
        body: { deviceId: de, commandId: rid(), keyVersion: 2, effectiveSequence: 7, expectedControlRevision: 1, publicKey: new Signer().publicB64Url },
      });
      check('rotation loser succeeds on a fresh commandId', retry.status === 200 && retry.json.controlRevision === 2);
    }
  });

  await group('long-poll wait', async () => {
    const d7 = 'acc-wait-' + Math.random().toString(36).slice(2, 8);
    const s7 = new Signer();
    await api('POST', '/v1/devices', { body: { deviceId: d7, publicKey: s7.publicB64Url } });
    const p = api('GET', `/v1/devices/${d7}/wait?afterSequence=0`);
    await sleep(200);
    const c7 = chain(s7, d7, 1);
    await api('POST', `/v1/devices/${d7}/ingest`, { body: { requestId: rid(), events: [c7[0].event] } });
    const r = await p;
    check('wait returns the newly committed event', r.status === 200 && r.json.timeout === false && r.json.events.length === 1);
  });

  await group('compaction, verifiable 410 and recovery', async () => {
    const d8 = 'acc-cp-' + Math.random().toString(36).slice(2, 8);
    const s8 = new Signer();
    await api('POST', '/v1/devices', { body: { deviceId: d8, publicKey: s8.publicB64Url } });
    const c8 = chain(s8, d8, 12);
    await api('POST', `/v1/devices/${d8}/ingest`, { body: { requestId: rid(), events: c8.map((x) => x.event) } });

    const compact = await api('POST', '/v1/admin/compact', {
      admin: true,
      body: { deviceId: d8, commandId: 'cp-' + rid(), cutoffSequence: 6 },
    });
    check('manual checkpoint at cutoff 6', compact.status === 200 && compact.json.checkpoint.sequence === 6);

    // Independently verify the checkpoint: canonical bytes, signature and digest.
    const cp = compact.json.checkpoint;
    const { bytes: cpBytes } = canonicalCheckpoint(cp);
    const seedEnv = process.env.CHECKPOINT_SIGNING_KEY;
    let cpOk = false;
    if (seedEnv) {
      const priv = createPrivateKey({ key: Buffer.concat([ED25519_PKCS8_PREFIX, Buffer.from(seedEnv, 'base64url')]), format: 'der', type: 'pkcs8' });
      const pubRaw = publicKeyToRaw(createPublicKey(priv));
      cpOk = encodeB64Url(pubRaw) === cp.signerPublicKey
        ? verifyBytes(createPublicKey(priv), cpBytes, decodeB64Url(cp.signature))
        : false;
    }
    check('checkpoint signature verifies under shared key', cpOk);
    check('checkpoint digest equals cutoff event digest', cp.digest === c8[5].digest);

    const gone = await api('GET', `/v1/devices/${d8}/events`);
    check('reading behind checkpoint returns 410 with recovery point', gone.status === 410 && gone.json.error.details.resumeFromSequence === 7);
    const resumed = await api('GET', `/v1/devices/${d8}/events?afterSequence=6`);
    check('resumed read returns exactly the retained tail', resumed.status === 200 && resumed.json.events.map((e) => e.sequence).join() === '7,8,9,10,11,12');
  });

  await group('background worker compaction', async () => {
    const d9 = 'acc-bg-' + Math.random().toString(36).slice(2, 8);
    const s9 = new Signer();
    await api('POST', '/v1/devices', { body: { deviceId: d9, publicKey: s9.publicB64Url } });
    // retention=10, min=5: 40 visible events should yield cutoff 30.
    const c9 = chain(s9, d9, 40);
    await api('POST', `/v1/devices/${d9}/ingest`, { body: { requestId: rid(), events: c9.map((x) => x.event) } });
    let latest = null;
    for (let i = 0; i < 30; i++) {
      const r = await api('GET', `/v1/devices/${d9}/checkpoints/latest`);
      if (r.status === 200) { latest = r.json; break; }
      await sleep(1000);
    }
    check('worker eventually created a checkpoint for a real prefix', !!latest && latest.sequence >= 1 && latest.sequence <= 30);
    if (latest) {
      const { bytes } = canonicalCheckpoint(latest);
      const priv = createPrivateKey({ key: Buffer.concat([ED25519_PKCS8_PREFIX, Buffer.from(process.env.CHECKPOINT_SIGNING_KEY || '', 'base64url')]), format: 'der', type: 'pkcs8' });
      const sigOk = verifyBytes(createPublicKey(priv), bytes, decodeB64Url(latest.signature));
      check('worker checkpoint signature verifies', sigOk);
      check('worker checkpoint digest matches a real event', latest.digest === c9[latest.sequence - 1].digest);
    }
  });

  await group('request size limit', async () => {
    const tooBig = 'x'.repeat(16 * 1024 * 1024 + 1024);
    const r = await api('POST', '/v1/devices', { raw: tooBig });
    check('oversized body is 413', r.status === 413 && r.json.error.code === 'PAYLOAD_TOO_LARGE');
  });

  console.log(`\n==== acceptance summary: ${passed} passed, ${failures.length} failed ====`);
  if (failures.length) {
    for (const f of failures) console.log('FAILED:', f);
    process.exit(1);
  }
  console.log('ACCEPTANCE PASSED');
  process.exit(0);
}

main().catch((e) => {
  console.error('verify crashed:', e.stack || e.message);
  process.exit(1);
});
