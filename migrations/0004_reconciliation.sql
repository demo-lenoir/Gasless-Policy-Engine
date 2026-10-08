-- Fork evidence is immutable by block identity; canonical membership is a projection.
ALTER TABLE sponsorship_reservations
    ADD COLUMN outcome_state TEXT NOT NULL DEFAULT 'NOT_OBSERVED'
        CHECK (outcome_state IN ('NOT_OBSERVED','OBSERVED','CONFIRMING','FINAL','EXPIRED_UNUSED','REORGED','MANUAL_INTERVENTION')),
    ADD COLUMN outcome_tx_hash BYTEA CHECK (outcome_tx_hash IS NULL OR octet_length(outcome_tx_hash)=32),
    ADD COLUMN outcome_log_index BIGINT CHECK (outcome_log_index IS NULL OR outcome_log_index >= 0),
    ADD COLUMN execution_success BOOLEAN,
    ADD COLUMN finalized_head_number BIGINT CHECK (finalized_head_number IS NULL OR finalized_head_number >= 0),
    ADD COLUMN settled_at TIMESTAMPTZ;
CREATE UNIQUE INDEX sponsorship_reservations_userop_identity
    ON sponsorship_reservations(chain_id,user_op_hash) WHERE user_op_hash IS NOT NULL;
CREATE INDEX sponsorship_reservations_settlement_idx
    ON sponsorship_reservations(chain_id,valid_until,sponsorship_id)
    WHERE status='RESERVED' AND signed_artifact IS NOT NULL;
ALTER TABLE sponsorship_reservations ADD CONSTRAINT issued_userop_binding
    CHECK (signed_artifact IS NULL OR user_op_hash IS NOT NULL) NOT VALID;
CREATE FUNCTION preserve_userop_binding() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.user_op_hash IS NOT NULL AND OLD.user_op_hash IS DISTINCT FROM NEW.user_op_hash THEN
        RAISE EXCEPTION 'issued UserOperation identity is immutable' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER sponsorship_reservations_userop_immutable
    BEFORE UPDATE ON sponsorship_reservations FOR EACH ROW EXECUTE FUNCTION preserve_userop_binding();

CREATE TABLE reconciliation_checkpoints (
    chain_id NUMERIC(78,0) NOT NULL CHECK (chain_id > 0),
    entry_point BYTEA NOT NULL CHECK (octet_length(entry_point)=20),
    stream_id TEXT NOT NULL CHECK (length(stream_id) BETWEEN 1 AND 64),
    paymaster BYTEA NOT NULL CHECK (octet_length(paymaster)=20),
    confirmations BIGINT NOT NULL CHECK (confirmations > 0),
    max_reorg_depth BIGINT NOT NULL CHECK (max_reorg_depth > 0),
    expected_code_hash BYTEA CHECK (expected_code_hash IS NULL OR octet_length(expected_code_hash)=32),
    expected_genesis_hash BYTEA CHECK (expected_genesis_hash IS NULL OR octet_length(expected_genesis_hash)=32),
    block_number BIGINT NOT NULL CHECK (block_number >= 0),
    block_hash BYTEA NOT NULL CHECK (octet_length(block_hash)=32),
    block_time TIMESTAMPTZ NOT NULL,
    state TEXT NOT NULL DEFAULT 'HEALTHY' CHECK (state IN ('HEALTHY','MANUAL_INTERVENTION')),
    anomaly TEXT,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY(chain_id,entry_point,stream_id),
    UNIQUE(chain_id)
);

CREATE TABLE reconciliation_blocks (
    chain_id NUMERIC(78,0) NOT NULL CHECK (chain_id > 0),
    block_hash BYTEA NOT NULL CHECK (octet_length(block_hash)=32),
    block_number BIGINT NOT NULL CHECK (block_number >= 0),
    parent_hash BYTEA NOT NULL CHECK (octet_length(parent_hash)=32),
    block_time TIMESTAMPTZ NOT NULL,
    canonical BOOLEAN NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY(chain_id,block_hash)
);
CREATE UNIQUE INDEX reconciliation_blocks_canonical_height
    ON reconciliation_blocks(chain_id,block_number) WHERE canonical;

CREATE TABLE userop_observations (
    chain_id NUMERIC(78,0) NOT NULL CHECK (chain_id > 0),
    block_hash BYTEA NOT NULL CHECK (octet_length(block_hash)=32),
    transaction_hash BYTEA NOT NULL CHECK (octet_length(transaction_hash)=32),
    log_index BIGINT NOT NULL CHECK (log_index >= 0),
    block_number BIGINT NOT NULL CHECK (block_number >= 0),
    entry_point BYTEA NOT NULL CHECK (octet_length(entry_point)=20),
    user_op_hash BYTEA NOT NULL CHECK (octet_length(user_op_hash)=32),
    sponsorship_id BYTEA REFERENCES sponsorship_reservations(sponsorship_id),
    sender BYTEA NOT NULL CHECK (octet_length(sender)=20),
    paymaster BYTEA NOT NULL CHECK (octet_length(paymaster)=20),
    nonce NUMERIC(78,0) NOT NULL CHECK (nonce >= 0),
    execution_success BOOLEAN NOT NULL,
    actual_gas_cost_wei NUMERIC(78,0) NOT NULL CHECK (actual_gas_cost_wei >= 0),
    actual_gas_used NUMERIC(78,0) NOT NULL CHECK (actual_gas_used >= 0),
    canonical BOOLEAN NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY(chain_id,block_hash,transaction_hash,log_index),
    FOREIGN KEY(chain_id,block_hash) REFERENCES reconciliation_blocks(chain_id,block_hash)
);
CREATE INDEX userop_observations_sponsorship_idx
    ON userop_observations(sponsorship_id,block_number) WHERE canonical AND sponsorship_id IS NOT NULL;

CREATE TABLE actual_spend_ledger (
    sponsorship_id BYTEA PRIMARY KEY REFERENCES sponsorship_reservations(sponsorship_id),
    chain_id NUMERIC(78,0) NOT NULL CHECK (chain_id > 0),
    user_op_hash BYTEA NOT NULL CHECK (octet_length(user_op_hash)=32),
    block_hash BYTEA NOT NULL CHECK (octet_length(block_hash)=32),
    block_number BIGINT NOT NULL CHECK (block_number >= 0),
    transaction_hash BYTEA NOT NULL CHECK (octet_length(transaction_hash)=32),
    log_index BIGINT NOT NULL CHECK (log_index >= 0),
    reserved_wei NUMERIC(78,0) NOT NULL CHECK (reserved_wei > 0),
    actual_wei NUMERIC(78,0) NOT NULL CHECK (actual_wei >= 0),
    released_wei NUMERIC(78,0) NOT NULL CHECK (released_wei >= 0),
    execution_success BOOLEAN NOT NULL,
    finalized_head_number BIGINT NOT NULL CHECK (finalized_head_number >= block_number),
    settled_at TIMESTAMPTZ NOT NULL,
    CHECK (reserved_wei=actual_wei+released_wei),
    FOREIGN KEY(chain_id,block_hash,transaction_hash,log_index)
        REFERENCES userop_observations(chain_id,block_hash,transaction_hash,log_index)
);

CREATE TABLE reconciliation_anomalies (
    anomaly_id UUID PRIMARY KEY,
    chain_id NUMERIC(78,0) NOT NULL CHECK (chain_id > 0),
    entry_point BYTEA NOT NULL CHECK (octet_length(entry_point)=20),
    sponsorship_id BYTEA REFERENCES sponsorship_reservations(sponsorship_id),
    code TEXT NOT NULL,
    details JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(details)='object'),
    observed_at TIMESTAMPTZ NOT NULL,
    resolved_at TIMESTAMPTZ
);
CREATE INDEX reconciliation_anomalies_open_idx
    ON reconciliation_anomalies(chain_id,entry_point) WHERE resolved_at IS NULL;
