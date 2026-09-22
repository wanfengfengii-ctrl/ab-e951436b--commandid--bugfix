-- Global idempotency for admin commands.
--
-- A commandId is reserved GLOBALLY for the first admin command that commits
-- with it, across every command kind ('rotate', 'adjudicate', 'compact') and
-- every device. The primary key on admin_commands.command_id (added in 0001)
-- is the cross-instance arbitration point: two API instances contending for
-- the same commandId can only produce one first result, and the loser's
-- transaction rolls back without any partial write.
--
-- Application semantics (enforced in src/services/idempotency.mjs):
--   * same commandId + same kind + same request hash -> replay of the exact
--     first response ({replayed: true});
--   * same commandId with a different kind or different canonical content ->
--     stable HTTP 409 IDEMPOTENCY_CONFLICT identifying the first command.
--
-- No constraint change is required: command_id is already a globally unique
-- primary key and kind is intentionally NOT part of it. This migration only
-- records the invariant alongside the schema; replaying it is a no-op.
COMMENT ON TABLE admin_commands IS
  'Exactly one row per commandId, globally across kinds (rotate/adjudicate/compact) and devices. '
  'Reusing a committed commandId replays the stored response when kind+request_hash match, '
  'and otherwise deterministically conflicts (HTTP 409 IDEMPOTENCY_CONFLICT).';
