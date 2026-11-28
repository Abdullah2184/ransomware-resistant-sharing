-- Persistent relayed-transaction reconciliation and orphan blob tracking
-- (docs/specifications/TECHNICAL_SPECIFICATION.md §§7.13, 9.2 #10, 10.4.7).

CREATE TABLE gateway_relayed_transactions (
    tx_hash TEXT PRIMARY KEY,
    operation_kind TEXT NOT NULL CHECK (
        operation_kind IN (
            'file.create',
            'file.version_append',
            'file.version_restore',
            'file.envelope_update'
        )
    ),
    operation_id TEXT NOT NULL,
    actor_member_id TEXT NOT NULL,
    file_id TEXT NOT NULL,
    version_number BIGINT NOT NULL CHECK (version_number > 0),
    content_cid TEXT,
    envelope_set_cid TEXT NOT NULL,
    chain_id BIGINT NOT NULL CHECK (chain_id > 0),
    status TEXT NOT NULL CHECK (status IN ('pending', 'confirmed', 'reverted')),
    block_number BIGINT CHECK (block_number IS NULL OR block_number >= 0),
    block_hash TEXT,
    gas_used BIGINT CHECK (gas_used IS NULL OR gas_used >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX gateway_relayed_transactions_status_created
    ON gateway_relayed_transactions (status, created_at);

CREATE INDEX gateway_relayed_transactions_actor_created
    ON gateway_relayed_transactions (actor_member_id, created_at DESC);

CREATE TABLE gateway_orphan_blobs (
    cid TEXT PRIMARY KEY,
    blob_kind TEXT NOT NULL CHECK (blob_kind IN ('content', 'envelope')),
    uploader_member_id TEXT NOT NULL,
    file_id TEXT,
    version_number BIGINT CHECK (version_number IS NULL OR version_number > 0),
    tx_hash TEXT,
    reason TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('candidate', 'referenced', 'unpinned')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX gateway_orphan_blobs_status_created
    ON gateway_orphan_blobs (status, created_at);
