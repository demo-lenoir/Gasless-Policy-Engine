-- Phase 0 schema design. Runtime migration execution is introduced with accounting implementation.
-- Addresses are exactly 20 bytes; hashes and identifiers are exactly 32 bytes.

CREATE TABLE policy_versions (
    version BIGINT PRIMARY KEY CHECK (version > 0),
    policy JSONB NOT NULL CHECK (jsonb_typeof(policy) = 'object'),
    policy_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(policy_hash) = 32),
    published_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE service_controls (
    chain_id NUMERIC(78,0) PRIMARY KEY CHECK (chain_id > 0),
    issuance_disabled BOOLEAN NOT NULL DEFAULT FALSE,
    generation BIGINT NOT NULL DEFAULT 1 CHECK (generation > 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE sponsorship_requests (
    request_id UUID PRIMARY KEY,
    client_scope TEXT NOT NULL CHECK (length(client_scope) BETWEEN 1 AND 128),
    idempotency_key TEXT NOT NULL CHECK (length(idempotency_key) BETWEEN 16 AND 128),
    request_fingerprint BYTEA NOT NULL CHECK (octet_length(request_fingerprint) = 32),
    chain_id NUMERIC(78,0) NOT NULL CHECK (chain_id > 0),
    sender BYTEA NOT NULL CHECK (octet_length(sender) = 20),
    target BYTEA NOT NULL CHECK (octet_length(target) = 20),
    selector BYTEA NOT NULL CHECK (octet_length(selector) = 4),
    policy_version BIGINT NOT NULL REFERENCES policy_versions(version),
    decision TEXT NOT NULL CHECK (decision IN ('APPROVED', 'DENIED')),
    reason TEXT NOT NULL,
    observation_block_number NUMERIC(78,0),
    observation_block_hash BYTEA CHECK (observation_block_hash IS NULL OR octet_length(observation_block_hash) = 32),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (client_scope, idempotency_key)
);

-- One row per chain/day/scope. GLOBAL uses the all-zero 20-byte subject.
-- Limits may be lowered below current usage; the reservation transaction then rejects new holds.
CREATE TABLE budget_periods (
    chain_id NUMERIC(78,0) NOT NULL CHECK (chain_id > 0),
    period_start DATE NOT NULL,
    scope TEXT NOT NULL CHECK (scope IN ('GLOBAL', 'SENDER')),
    subject BYTEA NOT NULL CHECK (octet_length(subject) = 20),
    limit_wei NUMERIC(78,0) NOT NULL CHECK (limit_wei >= 0),
    limit_count BIGINT CHECK (limit_count IS NULL OR limit_count >= 0),
    held_wei NUMERIC(78,0) NOT NULL DEFAULT 0 CHECK (held_wei >= 0),
    consumed_wei NUMERIC(78,0) NOT NULL DEFAULT 0 CHECK (consumed_wei >= 0),
    held_count BIGINT NOT NULL DEFAULT 0 CHECK (held_count >= 0),
    consumed_count BIGINT NOT NULL DEFAULT 0 CHECK (consumed_count >= 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (chain_id, period_start, scope, subject),
    CHECK (scope <> 'GLOBAL' OR subject = decode(repeat('00', 20), 'hex'))
);

CREATE TABLE sponsorship_reservations (
    sponsorship_id BYTEA PRIMARY KEY CHECK (octet_length(sponsorship_id) = 32),
    request_id UUID NOT NULL UNIQUE REFERENCES sponsorship_requests(request_id),
    chain_id NUMERIC(78,0) NOT NULL CHECK (chain_id > 0),
    sender BYTEA NOT NULL CHECK (octet_length(sender) = 20),
    period_start DATE NOT NULL,
    reserved_cost_wei NUMERIC(78,0) NOT NULL CHECK (reserved_cost_wei > 0),
    actual_cost_wei NUMERIC(78,0) CHECK (actual_cost_wei IS NULL OR actual_cost_wei >= 0),
    status TEXT NOT NULL DEFAULT 'RESERVED' CHECK (status IN ('RESERVED', 'CONSUMED', 'EXPIRED', 'RELEASED')),
    valid_after TIMESTAMPTZ NOT NULL,
    valid_until TIMESTAMPTZ NOT NULL,
    typed_digest BYTEA CHECK (typed_digest IS NULL OR octet_length(typed_digest) = 32),
    signed_artifact BYTEA,
    user_op_hash BYTEA CHECK (user_op_hash IS NULL OR octet_length(user_op_hash) = 32),
    outcome_block_number NUMERIC(78,0),
    outcome_block_hash BYTEA CHECK (outcome_block_hash IS NULL OR octet_length(outcome_block_hash) = 32),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    issued_at TIMESTAMPTZ,
    transitioned_at TIMESTAMPTZ,
    CHECK (valid_until > valid_after),
    CHECK ((typed_digest IS NULL) = (signed_artifact IS NULL)),
    CHECK (issued_at IS NULL OR signed_artifact IS NOT NULL),
    CHECK (status <> 'RELEASED' OR signed_artifact IS NULL),
    CHECK (status <> 'CONSUMED' OR actual_cost_wei IS NOT NULL)
);

CREATE INDEX sponsorship_reservations_open_idx
    ON sponsorship_reservations (valid_until, chain_id)
    WHERE status = 'RESERVED';

CREATE TABLE audit_events (
    event_id UUID PRIMARY KEY,
    event_key TEXT NOT NULL UNIQUE,
    request_id UUID NOT NULL REFERENCES sponsorship_requests(request_id),
    sponsorship_id BYTEA CHECK (sponsorship_id IS NULL OR octet_length(sponsorship_id) = 32),
    policy_version BIGINT NOT NULL REFERENCES policy_versions(version),
    chain_id NUMERIC(78,0) NOT NULL CHECK (chain_id > 0),
    entry_point BYTEA NOT NULL CHECK (octet_length(entry_point) = 20),
    paymaster BYTEA NOT NULL CHECK (octet_length(paymaster) = 20),
    event_type TEXT NOT NULL,
    decision TEXT,
    reason TEXT NOT NULL,
    sender BYTEA NOT NULL CHECK (octet_length(sender) = 20),
    target BYTEA NOT NULL CHECK (octet_length(target) = 20),
    selector BYTEA NOT NULL CHECK (octet_length(selector) = 4),
    digest BYTEA CHECK (digest IS NULL OR octet_length(digest) = 32),
    expires_at TIMESTAMPTZ,
    details JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(details) = 'object'),
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX audit_events_request_idx ON audit_events (request_id, occurred_at);

-- Application roles must have INSERT/SELECT only on policy_versions and audit_events.
-- UPDATE/DELETE privileges are withheld; corrections are new policy versions or audit events.
