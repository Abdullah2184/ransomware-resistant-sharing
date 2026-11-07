CREATE TABLE indexer_checkpoints (
    chain_id BIGINT PRIMARY KEY,
    block_number BIGINT NOT NULL CHECK (block_number >= 0),
    block_hash CHAR(66) NOT NULL CHECK (block_hash ~ '^0x[0-9a-f]{64}$'),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE indexed_contract_events (
    chain_id BIGINT NOT NULL,
    block_number BIGINT NOT NULL CHECK (block_number >= 0),
    block_hash CHAR(66) NOT NULL CHECK (block_hash ~ '^0x[0-9a-f]{64}$'),
    transaction_hash CHAR(66) NOT NULL CHECK (transaction_hash ~ '^0x[0-9a-f]{64}$'),
    transaction_index BIGINT NOT NULL CHECK (transaction_index >= 0),
    log_index BIGINT NOT NULL CHECK (log_index >= 0),
    contract_address CHAR(42) NOT NULL CHECK (contract_address ~ '^0x[0-9a-f]{40}$'),
    topic0 CHAR(66) NOT NULL CHECK (topic0 ~ '^0x[0-9a-f]{64}$'),
    event_name TEXT NOT NULL,
    event_data JSONB NOT NULL,
    raw_topics JSONB NOT NULL,
    raw_data TEXT NOT NULL,
    PRIMARY KEY (chain_id, transaction_hash, log_index)
);

CREATE INDEX indexed_contract_events_block
    ON indexed_contract_events (chain_id, block_number, log_index);
CREATE INDEX indexed_contract_events_name
    ON indexed_contract_events (chain_id, event_name, block_number);

CREATE TABLE files_projection (
    file_id CHAR(66) PRIMARY KEY,
    organization_id CHAR(66),
    creator_member_id CHAR(66),
    display_name TEXT,
    parent_folder_id CHAR(66),
    file_status SMALLINT,
    current_version BIGINT,
    current_head_manifest_hash CHAR(66),
    updated_block_number BIGINT NOT NULL
);

CREATE INDEX files_projection_folder
    ON files_projection (organization_id, parent_folder_id, display_name);

CREATE TABLE folders_projection (
    folder_id CHAR(66) PRIMARY KEY,
    organization_id CHAR(66) NOT NULL,
    parent_folder_id CHAR(66) NOT NULL,
    display_name TEXT NOT NULL,
    updated_block_number BIGINT NOT NULL
);

CREATE TABLE versions_projection (
    file_id CHAR(66) NOT NULL,
    version_number BIGINT NOT NULL CHECK (version_number > 0),
    manifest_hash CHAR(66) NOT NULL,
    parent_manifest_hash CHAR(66) NOT NULL,
    epoch_id CHAR(66) NOT NULL,
    author_member_id CHAR(66) NOT NULL,
    author_signing_address CHAR(42) NOT NULL,
    content_cid TEXT NOT NULL,
    initial_envelope_set_cid TEXT NOT NULL,
    transaction_hash CHAR(66) NOT NULL,
    block_number BIGINT NOT NULL,
    PRIMARY KEY (file_id, version_number)
);

CREATE INDEX versions_projection_history
    ON versions_projection (file_id, version_number DESC);

CREATE TABLE members_projection (
    member_id CHAR(66) PRIMARY KEY,
    organization_id CHAR(66) NOT NULL,
    signing_address CHAR(42) NOT NULL,
    member_status SMALLINT NOT NULL,
    updated_block_number BIGINT NOT NULL
);

CREATE TABLE access_projection (
    file_id CHAR(66) NOT NULL,
    member_id CHAR(66) NOT NULL,
    permission SMALLINT NOT NULL CHECK (permission IN (0, 1)),
    granted BOOLEAN NOT NULL,
    actor TEXT NOT NULL,
    proposal_id CHAR(66) NOT NULL,
    updated_block_number BIGINT NOT NULL,
    PRIMARY KEY (file_id, member_id, permission)
);

CREATE INDEX access_projection_member
    ON access_projection (member_id, file_id);

CREATE TABLE envelope_sets_projection (
    file_id CHAR(66) NOT NULL,
    version_number BIGINT NOT NULL,
    epoch_id CHAR(66) NOT NULL,
    envelope_set_cid TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision >= 0),
    updated_block_number BIGINT NOT NULL,
    PRIMARY KEY (file_id, version_number)
);

CREATE TABLE member_keys_projection (
    member_id CHAR(66) NOT NULL,
    key_version INTEGER NOT NULL CHECK (key_version > 0),
    key_kind TEXT NOT NULL CHECK (key_kind IN ('signing', 'encryption')),
    key_status SMALLINT NOT NULL CHECK (key_status BETWEEN 1 AND 4),
    updated_block_number BIGINT NOT NULL,
    PRIMARY KEY (member_id, key_version, key_kind)
);
