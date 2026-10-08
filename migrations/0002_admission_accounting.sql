-- All-chain and per-chain spend caps share a period; sender count is an admission rate limit.
ALTER TABLE budget_periods DROP CONSTRAINT budget_periods_chain_id_check;
ALTER TABLE budget_periods ADD CONSTRAINT budget_periods_chain_id_check CHECK (chain_id >= 0);
ALTER TABLE budget_periods DROP CONSTRAINT budget_periods_scope_check;
ALTER TABLE budget_periods ADD CONSTRAINT budget_periods_scope_check CHECK (scope IN ('ALL_CHAINS', 'GLOBAL', 'SENDER'));
ALTER TABLE budget_periods ADD CONSTRAINT budget_periods_scope_identity_check CHECK (
    (scope = 'ALL_CHAINS' AND chain_id = 0 AND subject = decode(repeat('00', 20), 'hex')) OR
    (scope = 'GLOBAL' AND chain_id > 0 AND subject = decode(repeat('00', 20), 'hex')) OR
    (scope = 'SENDER' AND chain_id > 0 AND subject <> decode(repeat('00', 20), 'hex'))
);
ALTER TABLE budget_periods ADD COLUMN admitted_count BIGINT NOT NULL DEFAULT 0 CHECK (admitted_count >= 0);
ALTER TABLE budget_periods ADD CONSTRAINT budget_periods_count_identity_check CHECK (
    (scope = 'SENDER' AND limit_count IS NOT NULL AND limit_count > 0 AND admitted_count >= held_count + consumed_count) OR
    (scope <> 'SENDER' AND limit_count IS NULL AND admitted_count = 0)
);

ALTER TABLE sponsorship_requests DROP CONSTRAINT sponsorship_requests_decision_check;
ALTER TABLE sponsorship_requests ADD CONSTRAINT sponsorship_requests_decision_check CHECK (decision IN ('PENDING', 'APPROVED', 'DENIED'));
ALTER TABLE sponsorship_requests ADD COLUMN updated_at TIMESTAMPTZ NOT NULL DEFAULT now();

ALTER TABLE audit_events ALTER COLUMN paymaster DROP NOT NULL;
ALTER TABLE audit_events ADD COLUMN request_fingerprint BYTEA CHECK (request_fingerprint IS NULL OR octet_length(request_fingerprint) = 32);
ALTER TABLE audit_events ADD CONSTRAINT audit_events_sponsorship_fk FOREIGN KEY (sponsorship_id) REFERENCES sponsorship_reservations(sponsorship_id);
CREATE INDEX audit_events_sponsorship_idx ON audit_events (sponsorship_id, occurred_at) WHERE sponsorship_id IS NOT NULL;

DROP INDEX sponsorship_reservations_open_idx;
CREATE INDEX sponsorship_reservations_expiry_idx ON sponsorship_reservations (valid_until, sponsorship_id)
    WHERE status = 'RESERVED' AND issued_at IS NULL AND signed_artifact IS NULL;
