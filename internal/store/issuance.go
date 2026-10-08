package store

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/demo-lenoir/gasless-policy-engine/internal/admission"
	"github.com/demo-lenoir/gasless-policy-engine/internal/authorization"
	"github.com/demo-lenoir/gasless-policy-engine/internal/issuance"
	"github.com/demo-lenoir/gasless-policy-engine/internal/policy"
	"github.com/demo-lenoir/gasless-policy-engine/internal/signing"
	"github.com/demo-lenoir/gasless-policy-engine/internal/userop"
	"github.com/jackc/pgx/v5"
)

type signingRow struct {
	requestID, decision, status, chain, cost                                                string
	version                                                                                 int64
	requestPayload, fingerprint, policyHash, sender, target, selector, claimToken, artifact []byte
	claimGeneration                                                                         int64
	claimUntil                                                                              *time.Time
	validAfter, validUntil                                                                  time.Time
	revoked                                                                                 bool
}

func readSigningRow(ctx context.Context, tx pgx.Tx, id [32]byte) (signingRow, error) {
	var row signingRow
	err := tx.QueryRow(ctx, `SELECT r.request_id::text,q.decision,r.status,r.chain_id::text,r.reserved_cost_wei::text,
q.policy_version,q.request_payload,q.request_fingerprint,p.policy_hash,q.sender,q.target,q.selector,
r.signing_claim_token::text,r.signing_claim_generation,r.signing_claim_until,r.signed_artifact,
r.valid_after,r.valid_until,p.issuance_revoked
FROM sponsorship_reservations r JOIN sponsorship_requests q ON q.request_id=r.request_id
JOIN policy_versions p ON p.version=q.policy_version WHERE r.sponsorship_id=$1 FOR UPDATE OF r FOR SHARE OF p`, id[:]).Scan(
		&row.requestID, &row.decision, &row.status, &row.chain, &row.cost, &row.version, &row.requestPayload, &row.fingerprint, &row.policyHash, &row.sender, &row.target, &row.selector, &row.claimToken, &row.claimGeneration, &row.claimUntil, &row.artifact, &row.validAfter, &row.validUntil, &row.revoked)
	return row, err
}

func verifiedClaim(row signingRow, id [32]byte) (issuance.Claim, error) {
	if row.version <= 0 || len(row.requestPayload) == 0 || len(row.fingerprint) != 32 || len(row.policyHash) != 32 || len(row.sender) != 20 || len(row.target) != 20 || len(row.selector) != 4 {
		return issuance.Claim{}, errors.New("incomplete stored request")
	}
	var input policy.RequestInput
	if err := json.Unmarshal(row.requestPayload, &input); err != nil {
		return issuance.Claim{}, err
	}
	r, err := policy.Normalize(input)
	if err != nil {
		return issuance.Claim{}, err
	}
	fingerprint := admission.Fingerprint(r)
	call := r.Call()
	sender := r.Sender()
	if !bytes.Equal(fingerprint[:], row.fingerprint) || r.ChainID().String() != row.chain || !bytes.Equal(sender[:], row.sender) || !bytes.Equal(call.Target[:], row.target) || !bytes.Equal(call.Selector[:], row.selector) {
		return issuance.Claim{}, errors.New("stored request identity mismatch")
	}
	cost, err := policy.ParseUint256(row.cost)
	if err != nil {
		return issuance.Claim{}, err
	}
	expected, ok := policy.EstimatedUpperBound(r)
	if !ok || cost != expected.Uint256 {
		return issuance.Claim{}, errors.New("stored reservation amount mismatch")
	}
	claim := issuance.Claim{SponsorshipID: id, RequestID: row.requestID, Input: input, Fingerprint: fingerprint, PolicyVersion: policy.PolicyVersion(row.version), ReservedWei: cost, ValidAfter: row.validAfter, ValidUntil: row.validUntil, Generation: row.claimGeneration}
	copy(claim.PolicyHash[:], row.policyHash)
	return claim, nil
}

func (p *Postgres) ClaimSigning(ctx context.Context, id [32]byte, profile issuance.Profile, now time.Time, lease time.Duration) (issuance.ClaimResult, error) {
	if id == [32]byte{} || now.IsZero() || lease <= 0 || profile.PolicyVersion == 0 || profile.ChainID.IsZero() || profile.Paymaster.IsZero() || profile.EntryPoint.IsZero() || profile.ExpectedSigner.IsZero() || profile.AccountCodeHash == [32]byte{} {
		return issuance.ClaimResult{}, errors.New("invalid signing claim")
	}
	bounded, cancel := dbContext(ctx, p.timeout)
	defer cancel()
	tx, err := p.pool.Begin(bounded)
	if err != nil {
		return issuance.ClaimResult{}, err
	}
	defer tx.Rollback(bounded)
	row, err := readSigningRow(bounded, tx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return issuance.ClaimResult{Reason: issuance.ReservationStateConflict}, nil
	}
	if err != nil {
		return issuance.ClaimResult{}, err
	}
	if row.artifact != nil {
		if err = tx.Commit(bounded); err != nil {
			return issuance.ClaimResult{}, err
		}
		artifact, err := p.ReadAuthorization(bounded, id)
		if err != nil {
			return issuance.ClaimResult{}, err
		}
		if artifact == nil {
			return issuance.ClaimResult{}, errors.New("issued artifact cannot be reconstructed")
		}
		return issuance.ClaimResult{Reason: issuance.AlreadyIssued, Artifact: artifact}, nil
	}
	if row.decision != "APPROVED" || row.status != "RESERVED" || row.requestPayload == nil {
		return issuance.ClaimResult{Reason: issuance.ReservationStateConflict}, nil
	}
	if !now.Before(row.validUntil) {
		return issuance.ClaimResult{Reason: issuance.AuthorizationExpired}, nil
	}
	if row.revoked {
		return issuance.ClaimResult{Reason: issuance.PolicyRevoked}, nil
	}
	if row.version != int64(profile.PolicyVersion) || row.chain != profile.ChainID.String() {
		return issuance.ClaimResult{Reason: issuance.PolicyVersionConflict}, nil
	}
	matches, err := profileMatches(bounded, tx, profile)
	if err != nil {
		return issuance.ClaimResult{}, err
	}
	if !matches {
		return issuance.ClaimResult{Reason: issuance.PolicyVersionConflict}, nil
	}
	allowed, err := issuanceAllowed(bounded, tx, row.chain)
	if err != nil {
		return issuance.ClaimResult{}, err
	}
	if !allowed {
		return issuance.ClaimResult{Reason: issuance.EmergencyDisabled}, nil
	}
	if row.claimUntil != nil && now.Before(*row.claimUntil) {
		return issuance.ClaimResult{Reason: issuance.SigningInProgress}, nil
	}
	claim, err := verifiedClaim(row, id)
	if err != nil {
		return issuance.ClaimResult{}, err
	}
	token, err := uuid()
	if err != nil {
		return issuance.ClaimResult{}, err
	}
	if row.claimGeneration == int64(^uint64(0)>>1) {
		return issuance.ClaimResult{}, errors.New("signing generation exhausted")
	}
	claim.Token = token
	claim.Generation++
	claim.Profile = profile
	_, err = tx.Exec(bounded, `UPDATE sponsorship_reservations SET signing_claim_token=$1,signing_claim_generation=$2,signing_claim_until=$3 WHERE sponsorship_id=$4`, token, claim.Generation, now.Add(lease), id[:])
	if err != nil {
		return issuance.ClaimResult{}, err
	}
	if err = auditSigning(bounded, tx, claim, "SIGNING_CLAIMED", issuance.Issued, nil, nil, now); err != nil {
		return issuance.ClaimResult{}, err
	}
	if err = tx.Commit(bounded); err != nil {
		return issuance.ClaimResult{}, err
	}
	return issuance.ClaimResult{Reason: issuance.Issued, Claim: claim}, nil
}

func issuanceAllowed(ctx context.Context, tx pgx.Tx, chain string) (bool, error) {
	var disabled bool
	err := tx.QueryRow(ctx, `SELECT issuance_disabled FROM service_controls WHERE chain_id=$1::numeric FOR SHARE`, chain).Scan(&disabled)
	if err != nil {
		return false, err
	}
	return !disabled, nil
}

func profileMatches(ctx context.Context, tx pgx.Tx, profile issuance.Profile) (bool, error) {
	var paymaster, entry, codeHash, signer []byte
	err := tx.QueryRow(ctx, `SELECT paymaster_address,entry_point,account_code_hash,signer_address FROM issuance_profiles WHERE policy_version=$1 AND chain_id=$2::numeric FOR SHARE`, int64(profile.PolicyVersion), profile.ChainID.String()).Scan(&paymaster, &entry, &codeHash, &signer)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return bytes.Equal(paymaster, profile.Paymaster[:]) && bytes.Equal(entry, profile.EntryPoint[:]) && bytes.Equal(codeHash, profile.AccountCodeHash[:]) && bytes.Equal(signer, profile.ExpectedSigner[:]), nil
}

func checkClaim(ctx context.Context, tx pgx.Tx, row signingRow, c issuance.Claim, now time.Time) (issuance.Reason, error) {
	if !now.Before(row.validUntil) {
		return issuance.AuthorizationExpired, nil
	}
	if row.artifact != nil || row.claimToken == nil || string(row.claimToken) != c.Token || row.claimGeneration != c.Generation || row.claimUntil == nil || !now.Before(*row.claimUntil) {
		return issuance.SigningClaimLost, nil
	}
	if row.decision != "APPROVED" || row.status != "RESERVED" {
		return issuance.ReservationStateConflict, nil
	}
	if row.revoked {
		return issuance.PolicyRevoked, nil
	}
	if row.version != int64(c.Profile.PolicyVersion) || row.chain != c.Profile.ChainID.String() {
		return issuance.PolicyVersionConflict, nil
	}
	matches, err := profileMatches(ctx, tx, c.Profile)
	if err != nil {
		return "", err
	}
	if !matches {
		return issuance.PolicyVersionConflict, nil
	}
	allowed, err := issuanceAllowed(ctx, tx, row.chain)
	if err != nil {
		return "", err
	}
	if !allowed {
		return issuance.EmergencyDisabled, nil
	}
	return issuance.Issued, nil
}

func (p *Postgres) CheckSigningClaim(ctx context.Context, c issuance.Claim, now time.Time) (issuance.Reason, error) {
	bounded, cancel := dbContext(ctx, p.timeout)
	defer cancel()
	tx, err := p.pool.Begin(bounded)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(bounded)
	row, err := readSigningRow(bounded, tx, c.SponsorshipID)
	if err != nil {
		return "", err
	}
	reason, err := checkClaim(bounded, tx, row, c, now)
	if err != nil {
		return "", err
	}
	if err = tx.Commit(bounded); err != nil {
		return "", err
	}
	return reason, nil
}

func (p *Postgres) CommitAuthorization(ctx context.Context, c issuance.Claim, a issuance.Artifact, now time.Time) (issuance.Reason, error) {
	if c.SponsorshipID != a.SponsorshipID || c.RequestID != a.RequestID || c.PolicyVersion != a.PolicyVersion || c.PolicyHash != a.PolicyHash || !c.ValidAfter.Equal(a.ValidAfter) || !c.ValidUntil.Equal(a.ValidUntil) || now.IsZero() || c.Profile.PolicyVersion != a.PolicyVersion || c.Profile.ChainID != a.ChainID || c.Profile.Paymaster != a.Paymaster || c.Profile.EntryPoint != a.EntryPoint || c.Profile.ExpectedSigner != a.Signer || c.Profile.AccountCodeHash != a.AccountCodeHash {
		return issuance.InvalidInput, nil
	}
	r, err := policy.Normalize(c.Input)
	if err != nil {
		return issuance.InvalidInput, nil
	}
	if admission.Fingerprint(r) != c.Fingerprint || r.ChainID() != a.ChainID || r.EntryPoint() != a.EntryPoint {
		return issuance.InvalidInput, nil
	}
	auth, err := authorization.Build(r, c.SponsorshipID, c.PolicyVersion, c.PolicyHash, a.AccountCodeHash, c.ReservedWei, c.ValidAfter, c.ValidUntil)
	if err != nil {
		return issuance.InvalidInput, nil
	}
	domain, err := authorization.NewDomain(a.ChainID, a.Paymaster)
	if err != nil {
		return issuance.InvalidInput, nil
	}
	digest, err := authorization.Digest(domain, auth)
	if err != nil || digest != a.Digest {
		return issuance.InvalidInput, nil
	}
	if err = signing.VerifySignature(digest, a.Signature[:], a.Signer); err != nil {
		return issuance.InvalidSignature, nil
	}
	data, err := auth.PaymasterData()
	if err != nil || data != a.PaymasterData {
		return issuance.InvalidInput, nil
	}
	encoded, err := authorization.EncodePaymasterAndData(domain, auth, a.Signature[:])
	if err != nil || !bytes.Equal(encoded, a.PaymasterAndData[:]) {
		return issuance.InvalidInput, nil
	}
	op, err := userop.Build(r, a)
	if err != nil {
		return issuance.InvalidInput, nil
	}
	userOpHash, err := userop.Hash(op, a.ChainID, a.EntryPoint)
	if err != nil {
		return issuance.InvalidInput, nil
	}
	bounded, cancel := dbContext(ctx, p.timeout)
	defer cancel()
	tx, err := p.pool.Begin(bounded)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(bounded)
	row, err := readSigningRow(bounded, tx, c.SponsorshipID)
	if err != nil {
		return "", err
	}
	reason, err := checkClaim(bounded, tx, row, c, now)
	if err != nil {
		return "", err
	}
	if reason != issuance.Issued {
		return reason, nil
	}
	stored, err := verifiedClaim(row, c.SponsorshipID)
	if err != nil {
		return "", err
	}
	if stored.Fingerprint != c.Fingerprint || stored.PolicyVersion != c.PolicyVersion || stored.PolicyHash != c.PolicyHash || stored.ReservedWei != c.ReservedWei || !stored.ValidAfter.Equal(c.ValidAfter) || !stored.ValidUntil.Equal(c.ValidUntil) {
		return issuance.ReservationStateConflict, nil
	}
	_, err = tx.Exec(bounded, `UPDATE sponsorship_reservations SET typed_digest=$1,signed_artifact=$2,authorization_data=$3,paymaster_address=$4,signer_address=$5,signature=$6,authorization_policy_hash=$7,account_code_hash=$8,issued_at=$9,user_op_hash=$10,signing_claim_token=NULL,signing_claim_until=NULL WHERE sponsorship_id=$11`, a.Digest[:], a.PaymasterAndData[:], a.PaymasterData[:], a.Paymaster[:], a.Signer[:], a.Signature[:], a.PolicyHash[:], a.AccountCodeHash[:], now, userOpHash[:], c.SponsorshipID[:])
	if err != nil {
		return "", err
	}
	if err = auditSigning(bounded, tx, c, "AUTHORIZATION_ISSUED", issuance.Issued, a.Digest[:], a.Signer[:], now); err != nil {
		return "", err
	}
	if err = tx.Commit(bounded); err != nil {
		return "", err
	}
	return issuance.Issued, nil
}

func (p *Postgres) FailSigningClaim(ctx context.Context, c issuance.Claim, reason issuance.Reason, now time.Time) error {
	bounded, cancel := dbContext(ctx, p.timeout)
	defer cancel()
	tx, err := p.pool.Begin(bounded)
	if err != nil {
		return err
	}
	defer tx.Rollback(bounded)
	row, err := readSigningRow(bounded, tx, c.SponsorshipID)
	if err != nil {
		return err
	}
	if row.artifact != nil || row.claimToken == nil || string(row.claimToken) != c.Token || row.claimGeneration != c.Generation {
		return nil
	}
	_, err = tx.Exec(bounded, `UPDATE sponsorship_reservations SET signing_claim_token=NULL,signing_claim_until=NULL WHERE sponsorship_id=$1`, c.SponsorshipID[:])
	if err != nil {
		return err
	}
	event := "SIGNING_FAILED"
	if reason == issuance.EmergencyDisabled {
		event = "SIGNING_BLOCKED_EMERGENCY"
	}
	if err = auditSigning(bounded, tx, c, event, reason, nil, nil, now); err != nil {
		return err
	}
	return tx.Commit(bounded)
}

func auditSigning(ctx context.Context, tx pgx.Tx, c issuance.Claim, event string, reason issuance.Reason, digest, signer []byte, now time.Time) error {
	eventID, err := uuid()
	if err != nil {
		return err
	}
	key := fmt.Sprintf("%s:%s:%d", c.RequestID, event, c.Generation)
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(event_id,event_key,request_id,sponsorship_id,policy_version,chain_id,entry_point,paymaster,event_type,decision,reason,sender,target,selector,digest,request_fingerprint,expires_at,occurred_at,signer_address)
SELECT $1,$2,q.request_id,$3,q.policy_version,q.chain_id,decode(substr(q.request_payload->>'entry_point',3),'hex'),$11::bytea,$4,$4,$5,q.sender,q.target,q.selector,$6,q.request_fingerprint,$7,$8,$9 FROM sponsorship_requests q WHERE q.request_id=$10`, eventID, key, c.SponsorshipID[:], event, string(reason), digest, c.ValidUntil, now, signer, c.RequestID, c.Profile.Paymaster[:])
	return err
}

func (p *Postgres) ReadAuthorization(ctx context.Context, id [32]byte) (*issuance.Artifact, error) {
	bounded, cancel := dbContext(ctx, p.timeout)
	defer cancel()
	var a issuance.Artifact
	var requestPayload []byte
	var chain, cost string
	var version int64
	var digest, signature, data, encoded, paymaster, signer, accountHash, policyHash []byte
	var publishedHash, profilePaymaster, profileEntry, profileCodeHash, profileSigner []byte
	err := p.pool.QueryRow(bounded, `SELECT r.request_id::text,q.policy_version,q.request_payload,r.chain_id::text,r.reserved_cost_wei::text,r.valid_after,r.valid_until,r.typed_digest,r.signature,r.authorization_data,r.signed_artifact,r.paymaster_address,r.signer_address,r.account_code_hash,r.authorization_policy_hash,p.policy_hash,i.paymaster_address,i.entry_point,i.account_code_hash,i.signer_address
FROM sponsorship_reservations r JOIN sponsorship_requests q ON q.request_id=r.request_id JOIN policy_versions p ON p.version=q.policy_version JOIN issuance_profiles i ON i.policy_version=q.policy_version AND i.chain_id=q.chain_id WHERE r.sponsorship_id=$1 AND r.signed_artifact IS NOT NULL`, id[:]).Scan(&a.RequestID, &version, &requestPayload, &chain, &cost, &a.ValidAfter, &a.ValidUntil, &digest, &signature, &data, &encoded, &paymaster, &signer, &accountHash, &policyHash, &publishedHash, &profilePaymaster, &profileEntry, &profileCodeHash, &profileSigner)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(digest) != 32 || len(signature) != 65 || len(data) != authorization.PaymasterDataLength || len(encoded) != authorization.PaymasterAndDataLength || len(paymaster) != 20 || len(signer) != 20 || len(accountHash) != 32 || len(policyHash) != 32 {
		return nil, errors.New("incomplete stored artifact")
	}
	if !bytes.Equal(policyHash, publishedHash) || !bytes.Equal(paymaster, profilePaymaster) || !bytes.Equal(signer, profileSigner) || !bytes.Equal(accountHash, profileCodeHash) {
		return nil, errors.New("stored artifact profile mismatch")
	}
	a.SponsorshipID = id
	a.PolicyVersion = policy.PolicyVersion(version)
	copy(a.Digest[:], digest)
	copy(a.Signature[:], signature)
	copy(a.PaymasterData[:], data)
	copy(a.PaymasterAndData[:], encoded)
	copy(a.Paymaster[:], paymaster)
	copy(a.Signer[:], signer)
	copy(a.AccountCodeHash[:], accountHash)
	copy(a.PolicyHash[:], policyHash)
	var input policy.RequestInput
	if err = json.Unmarshal(requestPayload, &input); err != nil {
		return nil, err
	}
	r, err := policy.Normalize(input)
	if err != nil {
		return nil, err
	}
	costValue, err := policy.ParseUint256(cost)
	if err != nil {
		return nil, err
	}
	if chain != r.ChainID().String() {
		return nil, errors.New("stored artifact chain mismatch")
	}
	entry := r.EntryPoint()
	if !bytes.Equal(entry[:], profileEntry) {
		return nil, errors.New("stored artifact EntryPoint mismatch")
	}
	a.ChainID = r.ChainID()
	a.EntryPoint = r.EntryPoint()
	auth, err := authorization.Build(r, id, a.PolicyVersion, a.PolicyHash, a.AccountCodeHash, costValue, a.ValidAfter, a.ValidUntil)
	if err != nil {
		return nil, err
	}
	domain, err := authorization.NewDomain(a.ChainID, a.Paymaster)
	if err != nil {
		return nil, err
	}
	recomputed, err := authorization.Digest(domain, auth)
	if err != nil || recomputed != a.Digest {
		return nil, errors.New("stored artifact digest mismatch")
	}
	if err = signing.VerifySignature(recomputed, a.Signature[:], a.Signer); err != nil {
		return nil, err
	}
	expectedData, _ := auth.PaymasterData()
	expectedEncoding, _ := authorization.EncodePaymasterAndData(domain, auth, a.Signature[:])
	if expectedData != a.PaymasterData || !bytes.Equal(expectedEncoding, a.PaymasterAndData[:]) {
		return nil, errors.New("stored artifact encoding mismatch")
	}
	return &a, nil
}

func SponsorshipIDHex(id [32]byte) string { return hex.EncodeToString(id[:]) }

// MarkExpiredArtifacts records elapsed authorizations without releasing their economic holds.
// Outcome reconciliation must establish whether an operation landed before returning capacity.
func (p *Postgres) MarkExpiredArtifacts(ctx context.Context, now time.Time, limit int) (int, error) {
	if now.IsZero() || limit < 1 || limit > 1000 {
		return 0, errors.New("invalid authorization expiration batch")
	}
	bounded, cancel := dbContext(ctx, p.timeout)
	defer cancel()
	tx, err := p.pool.Begin(bounded)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(bounded)
	rows, err := tx.Query(bounded, `SELECT sponsorship_id FROM sponsorship_reservations WHERE signed_artifact IS NOT NULL AND authorization_expired_at IS NULL AND valid_until<$1 ORDER BY valid_until,sponsorship_id LIMIT $2 FOR UPDATE SKIP LOCKED`, now.UTC(), limit)
	if err != nil {
		return 0, err
	}
	var ids [][]byte
	for rows.Next() {
		var id []byte
		if err = rows.Scan(&id); err != nil {
			break
		}
		ids = append(ids, id)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return 0, err
	}
	for _, id := range ids {
		_, err = tx.Exec(bounded, `UPDATE sponsorship_reservations SET authorization_expired_at=$1 WHERE sponsorship_id=$2`, now.UTC(), id)
		if err != nil {
			return 0, err
		}
		eventID, e := uuid()
		if e != nil {
			return 0, e
		}
		_, err = tx.Exec(bounded, `INSERT INTO audit_events(event_id,event_key,request_id,sponsorship_id,policy_version,chain_id,entry_point,paymaster,event_type,decision,reason,sender,target,selector,digest,request_fingerprint,expires_at,occurred_at,signer_address)
SELECT $1,q.request_id::text||':AUTHORIZATION_EXPIRED',q.request_id,r.sponsorship_id,q.policy_version,q.chain_id,decode(substr(q.request_payload->>'entry_point',3),'hex'),r.paymaster_address,'AUTHORIZATION_EXPIRED','AUTHORIZATION_EXPIRED','AUTHORIZATION_EXPIRED',q.sender,q.target,q.selector,r.typed_digest,q.request_fingerprint,r.valid_until,$2,r.signer_address FROM sponsorship_reservations r JOIN sponsorship_requests q ON q.request_id=r.request_id WHERE r.sponsorship_id=$3`, eventID, now.UTC(), id)
		if err != nil {
			return 0, err
		}
	}
	if err = tx.Commit(bounded); err != nil {
		return 0, err
	}
	if observer, ok := p.observer.(interface{ ArtifactExpired(int) }); ok && len(ids) > 0 {
		observer.ArtifactExpired(len(ids))
	}
	return len(ids), nil
}
