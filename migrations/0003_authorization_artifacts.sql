-- Persist the normalized draft before a signing claim can be acquired.
ALTER TABLE sponsorship_requests ADD COLUMN request_payload JSONB
    CHECK (request_payload IS NULL OR jsonb_typeof(request_payload) = 'object');
ALTER TABLE policy_versions ADD COLUMN issuance_revoked BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE issuance_profiles (
    policy_version BIGINT NOT NULL REFERENCES policy_versions(version),
    chain_id NUMERIC(78,0) NOT NULL CHECK (chain_id > 0),
    paymaster_address BYTEA NOT NULL CHECK (octet_length(paymaster_address) = 20 AND paymaster_address <> decode(repeat('00',20),'hex')),
    entry_point BYTEA NOT NULL CHECK (octet_length(entry_point) = 20 AND entry_point <> decode(repeat('00',20),'hex')),
    account_code_hash BYTEA NOT NULL CHECK (octet_length(account_code_hash) = 32 AND account_code_hash <> decode(repeat('00',32),'hex')),
    signer_address BYTEA NOT NULL CHECK (octet_length(signer_address) = 20 AND signer_address <> decode(repeat('00',20),'hex')),
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (policy_version, chain_id)
);

CREATE FUNCTION preserve_issuance_profile() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'issuance profile is immutable' USING ERRCODE = '23514';
END $$;
CREATE TRIGGER issuance_profiles_immutable
    BEFORE UPDATE OR DELETE ON issuance_profiles FOR EACH ROW EXECUTE FUNCTION preserve_issuance_profile();

ALTER TABLE sponsorship_reservations
    ADD COLUMN signing_claim_token UUID,
    ADD COLUMN signing_claim_generation BIGINT NOT NULL DEFAULT 0 CHECK (signing_claim_generation >= 0),
    ADD COLUMN signing_claim_until TIMESTAMPTZ,
    ADD COLUMN authorization_data BYTEA CHECK (authorization_data IS NULL OR octet_length(authorization_data) = 116),
    ADD COLUMN paymaster_address BYTEA CHECK (paymaster_address IS NULL OR octet_length(paymaster_address) = 20),
    ADD COLUMN signer_address BYTEA CHECK (signer_address IS NULL OR octet_length(signer_address) = 20),
    ADD COLUMN account_code_hash BYTEA CHECK (account_code_hash IS NULL OR octet_length(account_code_hash) = 32),
    ADD COLUMN signature BYTEA CHECK (signature IS NULL OR octet_length(signature) = 65),
    ADD COLUMN authorization_policy_hash BYTEA CHECK (authorization_policy_hash IS NULL OR octet_length(authorization_policy_hash) = 32),
    ADD COLUMN authorization_expired_at TIMESTAMPTZ CHECK (authorization_expired_at IS NULL OR signed_artifact IS NOT NULL),
    ADD CONSTRAINT sponsorship_reservations_artifact_length CHECK (signed_artifact IS NULL OR octet_length(signed_artifact) = 243),
    ADD CONSTRAINT sponsorship_reservations_claim_pair CHECK ((signing_claim_token IS NULL) = (signing_claim_until IS NULL)),
    ADD CONSTRAINT sponsorship_reservations_issued_no_claim CHECK (signed_artifact IS NULL OR signing_claim_token IS NULL),
    ADD CONSTRAINT sponsorship_reservations_artifact_complete CHECK (
        (signed_artifact IS NULL AND typed_digest IS NULL AND authorization_data IS NULL AND paymaster_address IS NULL
            AND signer_address IS NULL AND signature IS NULL AND authorization_policy_hash IS NULL AND account_code_hash IS NULL AND issued_at IS NULL)
        OR
        (signed_artifact IS NOT NULL AND typed_digest IS NOT NULL AND authorization_data IS NOT NULL AND paymaster_address IS NOT NULL
            AND signer_address IS NOT NULL AND signature IS NOT NULL AND authorization_policy_hash IS NOT NULL AND account_code_hash IS NOT NULL AND issued_at IS NOT NULL)
    );

ALTER TABLE audit_events ADD COLUMN signer_address BYTEA
    CHECK (signer_address IS NULL OR octet_length(signer_address) = 20);

CREATE FUNCTION preserve_issued_authorization() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.signed_artifact IS NOT NULL AND ROW(
        OLD.sponsorship_id, OLD.request_id, OLD.chain_id, OLD.sender, OLD.period_start,
        OLD.reserved_cost_wei, OLD.valid_after, OLD.valid_until, OLD.typed_digest,
        OLD.signed_artifact, OLD.authorization_data, OLD.paymaster_address,
        OLD.signer_address, OLD.signature, OLD.authorization_policy_hash, OLD.account_code_hash, OLD.issued_at
    ) IS DISTINCT FROM ROW(
        NEW.sponsorship_id, NEW.request_id, NEW.chain_id, NEW.sender, NEW.period_start,
        NEW.reserved_cost_wei, NEW.valid_after, NEW.valid_until, NEW.typed_digest,
        NEW.signed_artifact, NEW.authorization_data, NEW.paymaster_address,
        NEW.signer_address, NEW.signature, NEW.authorization_policy_hash, NEW.account_code_hash, NEW.issued_at
    ) THEN
        RAISE EXCEPTION 'issued authorization is immutable' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER sponsorship_reservations_issued_immutable
    BEFORE UPDATE ON sponsorship_reservations FOR EACH ROW EXECUTE FUNCTION preserve_issued_authorization();

CREATE FUNCTION preserve_request_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.request_payload IS NOT NULL AND ROW(
        OLD.request_fingerprint, OLD.chain_id, OLD.sender, OLD.target, OLD.selector,
        OLD.policy_version, OLD.request_payload
    ) IS DISTINCT FROM ROW(
        NEW.request_fingerprint, NEW.chain_id, NEW.sender, NEW.target, NEW.selector,
        NEW.policy_version, NEW.request_payload
    ) THEN
        RAISE EXCEPTION 'admitted request identity is immutable' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER sponsorship_requests_identity_immutable
    BEFORE UPDATE ON sponsorship_requests FOR EACH ROW EXECUTE FUNCTION preserve_request_identity();

CREATE FUNCTION preserve_published_policy() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.policy IS DISTINCT FROM NEW.policy OR OLD.policy_hash IS DISTINCT FROM NEW.policy_hash OR (OLD.issuance_revoked AND NOT NEW.issuance_revoked) THEN
        RAISE EXCEPTION 'published policy is immutable' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER policy_versions_published_immutable
    BEFORE UPDATE ON policy_versions FOR EACH ROW EXECUTE FUNCTION preserve_published_policy();

CREATE INDEX sponsorship_reservations_signed_expiry_idx
    ON sponsorship_reservations (valid_until, sponsorship_id)
    WHERE signed_artifact IS NOT NULL AND authorization_expired_at IS NULL;
