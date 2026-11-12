CREATE TABLE historical_read_access_projection (
    file_id CHAR(66) NOT NULL,
    version_number BIGINT NOT NULL CHECK (version_number > 0),
    member_id CHAR(66) NOT NULL,
    granted BOOLEAN NOT NULL,
    actor CHAR(42) NOT NULL,
    proposal_id CHAR(66) NOT NULL,
    updated_block_number BIGINT NOT NULL,
    PRIMARY KEY (file_id, version_number, member_id)
);

CREATE INDEX historical_read_access_projection_member
    ON historical_read_access_projection (member_id, file_id, version_number);
