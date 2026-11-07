CREATE TABLE organizations_projection (
    organization_id CHAR(66) PRIMARY KEY,
    authority CHAR(42) NOT NULL,
    updated_block_number BIGINT NOT NULL
);

CREATE TABLE indexer_projection_chain (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    chain_id BIGINT NOT NULL
);

ALTER TABLE members_projection
    ADD COLUMN signing_key_version INTEGER,
    ADD COLUMN encryption_key_version INTEGER,
    ADD COLUMN encryption_public_key CHAR(66);

ALTER TABLE member_keys_projection
    ADD COLUMN public_key CHAR(66);
