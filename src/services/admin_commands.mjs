'use strict';
// Global idempotency for administrative commands (rotate, adjudicate, compact).
//
// A commandId is reserved GLOBALLY, across every command kind, by the first
// successful command that commits an outcome. The admin_commands primary key
// on command_id alone (see migration 0003) is the single cross-instance
// arbiter shared by every API process:
//
//   * identical replay  - same kind AND same canonical request hash: the exact
//     first response is returned ({...response, replayed: true});
//   * divergent reuse   - a different kind or different content: a stable 409
//     IDEMPOTENCY_CONFLICT, identical on every retry;
//   * concurrent races  - only the first inserter wins; the loser's whole
//     transaction rolls back and it re-reads the winner, answering exactly as
//     a serialized request would (replay or 409) with no partial writes.
//
// Each command performs the lookup twice inside its single transaction: once
// before taking the device row lock and again immediately after it. Commands
// touching one device serialize on that lock, so the second read always sees a
// winner that committed in the gap. Contention across DIFFERENT devices is
// resolved by the unique constraint itself (handleAdminCommandRace).

import { errors } from '../errors.mjs';

export const ADMIN_COMMAND_PKEY = 'admin_commands_pkey';

/** True when an error is the global commandId unique-violation. */
export function isAdminCommandRace(err) {
  return !!err && err.code === '23505' && err.constraint === ADMIN_COMMAND_PKEY;
}

function idempotencyConflict(row, commandId, attemptedKind) {
  return errors.conflict(
    'IDEMPOTENCY_CONFLICT',
    `commandId ${commandId} was already used by a different admin command` +
      (row?.kind ? ` (first use: ${row.kind})` : ''),
    {
      commandId,
      attemptedKind,
      ...(row?.kind ? { firstKind: row.kind } : {}),
      ...(row?.device_id ? { firstDeviceId: row.device_id } : {}),
    }
  );
}

/**
 * Resolve against an already-loaded admin_commands row (null when the id is
 * still free). Returns the stored response for an identical replay, or throws
 * a stable 409 for divergent reuse.
 */
export function resolveExistingCommand(row, { kind, requestHash, commandId }) {
  if (!row) return null;
  if (row.kind === kind && row.request_hash === requestHash) {
    return { ...row.response, replayed: true };
  }
  throw idempotencyConflict(row, commandId, kind);
}

/**
 * Lookup + replay/conflict resolution inside a transaction. Call both before
 * and after acquiring the device row lock.
 * @returns the stored replay response, or null when the id is still free.
 */
export async function replayAdminCommand(client, { commandId, kind, requestHash }) {
  const { rows } = await client.query(
    `SELECT kind, device_id, request_hash, response
       FROM admin_commands WHERE command_id=$1`,
    [commandId]
  );
  return resolveExistingCommand(rows[0] ?? null, { kind, requestHash, commandId });
}

/** Store the first outcome for a commandId. */
export async function persistAdminCommand(client, {
  commandId, deviceId, kind, requestHash, response,
}) {
  await client.query(
    `INSERT INTO admin_commands (command_id, device_id, kind, request_hash, conflict, response)
     VALUES ($1,$2,$3,$4,false,$5)`,
    [commandId, deviceId, kind, requestHash, JSON.stringify(response)]
  );
}

/**
 * Post-rollback arbitration for an INSERT that lost the global id race - the
 * typical shape of contention across two different devices or API instances.
 * The caller's transaction has already rolled back, so this re-reads the
 * committed winner on a fresh connection and returns exactly what a serialized
 * request would have returned: stored response for identical content, stable
 * 409 otherwise. Any unrelated error is rethrown unchanged.
 */
export async function handleAdminCommandRace(pool, err, { commandId, kind, requestHash }) {
  if (!isAdminCommandRace(err)) throw err;
  const { rows } = await pool.query(
    `SELECT kind, device_id, request_hash, response
       FROM admin_commands WHERE command_id=$1`,
    [commandId]
  );
  if (rows.length === 0) throw errors.internal('idempotency record vanished');
  return resolveExistingCommand(rows[0], { kind, requestHash, commandId });
}
