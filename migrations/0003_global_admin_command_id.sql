-- Global reservation of administrative commandId across ALL command kinds.
--
-- The table has always carried a single-column PRIMARY KEY on command_id, so
-- the DATABASE already enforced global uniqueness: one commandId could only
-- ever be stored once whether it was first used by a rotation, an
-- adjudication or a compaction. The defect was in the application, which
-- looked prior rows up with `WHERE command_id = $1 AND kind = $2` and
-- therefore treated the namespace as per-kind: a cross-kind reuse passed the
-- replay check, ran the command, and only failed at the final INSERT with a
-- raw unique violation, surfaced to clients as HTTP 500 INTERNAL_ERROR.
--
-- This migration makes the global invariant explicit and self-healing on any
-- deployment whose primary key differs (e.g. an older build keyed by
-- (command_id, kind)): colliding rows are collapsed to their first stored
-- outcome and the key is rebuilt on command_id alone. On the shipped schema
-- the key is already exactly that, so nothing is rebuilt - only documentation
-- is added.
DO $$
DECLARE
  v_key text;
BEGIN
  SELECT i.indkey::text INTO v_key
    FROM pg_index i
    JOIN pg_constraint c ON c.conindid = i.indexrelid
   WHERE c.conrelid = 'admin_commands'::regclass AND c.contype = 'p';

  IF v_key IS DISTINCT FROM (
       SELECT attnum::text FROM pg_attribute
        WHERE attrelid = 'admin_commands'::regclass AND attname = 'command_id'
     ) THEN
    -- Keep only the physically-first stored outcome per command_id (the
    -- retained row replays exactly as before); dropped tokens resolve as
    -- idempotency conflicts if ever reused. ctid orders rows in physical
    -- insertion order.
    DELETE FROM admin_commands
     WHERE ctid NOT IN (SELECT min(ctid) FROM admin_commands GROUP BY command_id);

    ALTER TABLE admin_commands DROP CONSTRAINT admin_commands_pkey;
    ALTER TABLE admin_commands ADD PRIMARY KEY (command_id);
  END IF;
END $$;

COMMENT ON TABLE admin_commands IS
  'Idempotency record for admin commands. command_id is globally unique across kinds (rotate, adjudicate, compact): the first successful command owns the id forever; identical kind+content replays the stored response, different kind or content is a 409 IDEMPOTENCY_CONFLICT.';
