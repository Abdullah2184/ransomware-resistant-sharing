-- Additive hardening migration:
-- 1. Defense-in-depth BEFORE TRUNCATE trigger on append-only `gateway_audit_events`.
-- 2. Expression index for member audit queries (GET /v1/audit).
-- 3. Composite indexes matching folder listings, event replay cursor pagination,
--    and bounded session expiry pruning.

CREATE TRIGGER gateway_audit_no_truncate
    BEFORE TRUNCATE ON gateway_audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION reject_gateway_audit_mutation();

CREATE INDEX IF NOT EXISTS gateway_audit_events_actor_sequence
    ON gateway_audit_events ((record->>'actor_member_id'), sequence DESC);

CREATE INDEX IF NOT EXISTS folders_projection_parent
    ON folders_projection (organization_id, parent_folder_id, display_name, folder_id);

CREATE INDEX IF NOT EXISTS indexed_contract_events_replay_order
    ON indexed_contract_events (chain_id, block_number, transaction_index, log_index);

CREATE INDEX IF NOT EXISTS gateway_sessions_expiry
    ON gateway_sessions (expires_at);
