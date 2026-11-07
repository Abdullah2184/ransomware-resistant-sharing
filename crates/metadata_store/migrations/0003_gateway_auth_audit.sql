CREATE TABLE gateway_login_challenges (
    member_id CHAR(66) NOT NULL CHECK (member_id ~ '^0x[0-9a-f]{64}$'),
    nonce BYTEA NOT NULL CHECK (octet_length(nonce) = 32),
    issued_at BIGINT NOT NULL CHECK (issued_at > 0),
    expires_at BIGINT NOT NULL CHECK (expires_at > issued_at),
    audience TEXT NOT NULL CHECK (length(audience) BETWEEN 1 AND 512),
    protocol_version INTEGER NOT NULL CHECK (protocol_version = 1),
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (member_id, nonce)
);

CREATE INDEX gateway_login_challenges_expiry
    ON gateway_login_challenges (expires_at);

CREATE TABLE gateway_sessions (
    token_hash BYTEA PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    member_id CHAR(66) NOT NULL CHECK (member_id ~ '^0x[0-9a-f]{64}$'),
    expires_at BIGINT NOT NULL CHECK (expires_at > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX gateway_sessions_member_expiry
    ON gateway_sessions (member_id, expires_at);

CREATE TABLE gateway_used_access_nonces (
    member_id CHAR(66) NOT NULL CHECK (member_id ~ '^0x[0-9a-f]{64}$'),
    operation_nonce BYTEA NOT NULL CHECK (octet_length(operation_nonce) = 32),
    expires_at BIGINT NOT NULL CHECK (expires_at > 0),
    used_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (member_id, operation_nonce)
);

CREATE INDEX gateway_used_access_nonces_expiry
    ON gateway_used_access_nonces (expires_at);

CREATE TABLE gateway_rate_buckets (
    bucket_key TEXT PRIMARY KEY,
    tokens DOUBLE PRECISION NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE gateway_audit_events (
    sequence BIGSERIAL PRIMARY KEY,
    record JSONB NOT NULL,
    record_canonical TEXT NOT NULL,
    resource_type TEXT,
    resource_id TEXT,
    resource_version BIGINT,
    previous_hash BYTEA NOT NULL CHECK (octet_length(previous_hash) = 32),
    record_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(record_hash) = 32),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE FUNCTION reject_gateway_audit_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'gateway audit events are append-only';
END;
$$;

CREATE TRIGGER gateway_audit_no_update_or_delete
    BEFORE UPDATE OR DELETE ON gateway_audit_events
    FOR EACH ROW EXECUTE FUNCTION reject_gateway_audit_mutation();
