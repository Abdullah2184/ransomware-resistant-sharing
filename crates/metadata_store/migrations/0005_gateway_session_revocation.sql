-- Additive migration supporting explicit gateway session revocation (DELETE /v1/auth/session).

ALTER TABLE gateway_sessions
    ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS gateway_sessions_active_lookup
    ON gateway_sessions (token_hash)
    WHERE revoked_at IS NULL;
