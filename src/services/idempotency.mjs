'use strict';
// Global idempotency for admin commands (key rotation, adjudication, manual
// compaction). A commandId is reserved GLOBALLY, across every admin command
// type and every device, by a single row in admin_commands (whose primary key
// is command_id). The reservation exists only for commands that actually
// committed: a failed/aborted command inserts nothing and rolls back, so its
// commandId stays free.
//
// Semantics:
//  * same commandId + same kind + same request hash  -> replay of the exact
//    first response ({replayed: true});
//  * same commandId with a different kind OR different content -> stable 409
//    IDEMPOTENCY_CONFLICT carrying the first command's kind/device;
//  * two API instances contending for one commandId -> exactly one first
//    result. The contender that loses the admin_commands primary-key race has
//    already run inside a transaction: the unique violation rolls every write
//    back (no partial state) and the winner's committed row is re-read to
//    answer deterministically (replay or 409), mirroring ingest_requests.

import { withTransaction } from '../db/pool.mjs';
import { errors, ApiError } from '../errors.mjs';

export const ADMIN_COMMAND_KINDS = ['rotate', 'adjudicate', 'compact'];

function idempotencyConflict(commandId, stored, requestedKind) {
  const crossKind = stored.kind !== requestedKind;
  const message = crossKind
    ? `commandId ${commandId} was already used by a successful ${stored.kind} admin command; ` +
      'a commandId is globally reserved across all admin command types'
    : `commandId ${commandId} was already used with different parameters`;
  return errors.conflict('IDEMPOTENCY_CONFLICT', message, {
    commandId,
    existingKind: stored.kind,
    existingDeviceId: stored.device_id,
    requestedKind,
  });
}

/** Resolve a committed admin_commands row against an in-flight request. */
function resolveStored(row, { kind, requestHash }) {
  if (row.kind === kind && row.request_hash === requestHash) {
    return { ...row.response, replayed: true };
  }
  throw idempotencyConflict(row.response?.commandId ?? row.command_id, row, kind);
}

function isReservationRace(e) {
  return e?.code === '23505' && e?.constraint === 'admin_commands_pkey';
}

/**
 * Run `execute(client)` as a globally idempotent admin command.
 *
 * `execute` performs every side effect and returns the JSON response to store
 * and replay (a plain object), or null when there is nothing to reserve (e.g.
 * a compaction that was not eligible). The admin_commands row is written by
 * this wrapper, never by `execute`.
 *
 * @returns the first response with {replayed:false}, a stored response with
 *          {replayed:true}, or null when execute produced nothing
 */
export async function runIdempotentAdminCommand(pool, { commandId, kind, deviceId, requestHash }, execute) {
  const spec = { kind, requestHash };
  try {
    return await withTransaction(pool, async (client) => {
      // Global lookup: no kind filter. A reservation made by ANY admin command
      // type wins, before this transaction performs any write.
      const prior = await client.query(
        `SELECT command_id, kind, device_id, request_hash, response
           FROM admin_commands WHERE command_id=$1`,
        [commandId]
      );
      if (prior.rows.length) return resolveStored(prior.rows[0], spec);

      const response = await execute(client);
      if (response === null || response === undefined) return response;

      await client.query(
        `INSERT INTO admin_commands (command_id, device_id, kind, request_hash, conflict, response)
         VALUES ($1,$2,$3,$4,false,$5)`,
        [commandId, deviceId, kind, requestHash, JSON.stringify(response)]
      );
      return { ...response, replayed: false };
    });
  } catch (e) {
    // Application errors (including a conflict raised from a stored row) and
    // unrelated violations pass through unchanged.
    if (e instanceof ApiError) throw e;
    if (!isReservationRace(e)) throw e;

    // A concurrent contender on another API instance committed first. Its row
    // is now visible; our whole transaction was rolled back, so no partial
    // write survived. Answer from the winner's stored outcome.
    const { rows } = await pool.query(
      `SELECT command_id, kind, device_id, request_hash, response
         FROM admin_commands WHERE command_id=$1`,
      [commandId]
    );
    if (rows.length === 0) throw errors.internal('idempotency record vanished');
    return resolveStored(rows[0], spec);
  }
}
