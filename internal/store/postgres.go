package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/demo-lenoir/gasless-policy-engine/internal/admission"
	"github.com/demo-lenoir/gasless-policy-engine/internal/policy"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel"
)

type LifecycleObserver interface {
	ReservationTransition(Transition, string)
	AdmissionRetry()
}
type Postgres struct {
	pool     *pgxpool.Pool
	timeout  time.Duration
	observer LifecycleObserver
}

func (p *Postgres) SetObserver(observer LifecycleObserver) { p.observer = observer }

func Open(ctx context.Context, dsn string, maxConns int32, timeout time.Duration) (*Postgres, error) {
	if dsn == "" || maxConns <= 0 || timeout <= 0 {
		return nil, errors.New("database DSN, pool size, and timeout are required")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	cfg.MaxConns = maxConns
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	probe, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := pool.Ping(probe); err != nil {
		pool.Close()
		return nil, err
	}
	return &Postgres{pool: pool, timeout: timeout}, nil
}
func (p *Postgres) Close()              { p.pool.Close() }
func (p *Postgres) Pool() *pgxpool.Pool { return p.pool }

func uuid() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}
func randomID() ([]byte, error) { b := make([]byte, 32); _, err := rand.Read(b); return b, err }
func dbContext(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, d)
}
func retryable(err error) bool {
	var e *pgconn.PgError
	return errors.As(err, &e) && (e.Code == "40001" || e.Code == "40P01")
}
func (p *Postgres) Admit(ctx context.Context, c admission.Candidate) (admission.Result, error) {
	bounded, cancel := dbContext(ctx, p.timeout)
	defer cancel()
	var result admission.Result
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		result, err = p.admitOnce(bounded, c)
		if !retryable(err) {
			return result, err
		}
		if p.observer != nil {
			p.observer.AdmissionRetry()
		}
		if bounded.Err() != nil {
			break
		}
	}
	return admission.Result{}, err
}
func (p *Postgres) admitOnce(ctx context.Context, c admission.Candidate) (out admission.Result, err error) {
	ctx, span := otel.Tracer("gasless/store").Start(ctx, "admission.transaction")
	defer span.End()
	tx, err := p.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return out, err
	}
	defer tx.Rollback(ctx)
	var priorID, priorDecision, priorReason string
	var priorFingerprint []byte
	var priorVersion int64
	priorErr := tx.QueryRow(ctx, `SELECT request_id::text,request_fingerprint,decision,reason,policy_version FROM sponsorship_requests WHERE client_scope=$1 AND idempotency_key=$2 FOR UPDATE`, c.Scope, c.Key).Scan(&priorID, &priorFingerprint, &priorDecision, &priorReason, &priorVersion)
	if priorErr == nil {
		if hex.EncodeToString(priorFingerprint) != hex.EncodeToString(c.Fingerprint[:]) {
			return admission.Result{Reason: admission.IdempotencyConflict}, nil
		}
		out, err = existing(ctx, tx, priorID, priorDecision, priorReason, priorVersion, priorFingerprint)
		if err != nil {
			return out, err
		}
		if err = tx.Commit(ctx); err != nil {
			return admission.Result{}, err
		}
		return out, nil
	}
	if !errors.Is(priorErr, pgx.ErrNoRows) {
		return out, priorErr
	}
	version := int64(c.Decision.PolicyVersion)
	if version <= 0 {
		return out, errors.New("invalid policy version")
	}
	_, err = tx.Exec(ctx, `INSERT INTO policy_versions(version,policy,policy_hash,published_at) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, version, c.PolicyJSON, c.PolicyHash[:], c.Now)
	if err != nil {
		return out, err
	}
	var storedHash []byte
	err = tx.QueryRow(ctx, `SELECT policy_hash FROM policy_versions WHERE version=$1`, version).Scan(&storedHash)
	if err != nil {
		return out, err
	}
	if hex.EncodeToString(storedHash) != hex.EncodeToString(c.PolicyHash[:]) {
		return out, admission.ErrPolicyVersionConflict
	}
	if c.Profile != nil {
		profile := c.Profile
		if profile.ChainID != c.Request.ChainID() {
			return out, errors.New("issuance profile chain mismatch")
		}
		_, err = tx.Exec(ctx, `INSERT INTO issuance_profiles(policy_version,chain_id,paymaster_address,entry_point,account_code_hash,signer_address,created_at)
VALUES($1,$2::numeric,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`, version, profile.ChainID.String(), profile.Paymaster[:], profile.EntryPoint[:], profile.AccountCodeHash[:], profile.ExpectedSigner[:], c.Now)
		if err != nil {
			return out, err
		}
		var paymaster, entry, codeHash, signer []byte
		err = tx.QueryRow(ctx, `SELECT paymaster_address,entry_point,account_code_hash,signer_address FROM issuance_profiles WHERE policy_version=$1 AND chain_id=$2::numeric FOR SHARE`, version, profile.ChainID.String()).Scan(&paymaster, &entry, &codeHash, &signer)
		if err != nil {
			return out, err
		}
		if !bytes.Equal(paymaster, profile.Paymaster[:]) || !bytes.Equal(entry, profile.EntryPoint[:]) || !bytes.Equal(codeHash, profile.AccountCodeHash[:]) || !bytes.Equal(signer, profile.ExpectedSigner[:]) {
			return out, admission.ErrPolicyVersionConflict
		}
	}
	id, err := uuid()
	if err != nil {
		return out, err
	}
	call := c.Request.Call()
	requestPayload, err := json.Marshal(c.Request.CanonicalInput())
	if err != nil {
		return out, err
	}
	chain := c.Request.ChainID().String()
	sender := c.Request.Sender()
	_, err = tx.Exec(ctx, `INSERT INTO sponsorship_requests(request_id,client_scope,idempotency_key,request_fingerprint,chain_id,sender,target,selector,policy_version,decision,reason,created_at,updated_at,request_payload)
 VALUES($1,$2,$3,$4,$5::numeric,$6,$7,$8,$9,'PENDING','PENDING',$10,$10,$11::jsonb) ON CONFLICT (client_scope,idempotency_key) DO NOTHING`, id, c.Scope, c.Key, c.Fingerprint[:], chain, sender[:], call.Target[:], call.Selector[:], version, c.Now, requestPayload)
	if err != nil {
		return out, err
	}
	var requestID, decision, reason string
	var fingerprint []byte
	var storedVersion int64
	err = tx.QueryRow(ctx, `SELECT request_id::text,request_fingerprint,decision,reason,policy_version FROM sponsorship_requests WHERE client_scope=$1 AND idempotency_key=$2 FOR UPDATE`, c.Scope, c.Key).Scan(&requestID, &fingerprint, &decision, &reason, &storedVersion)
	if err != nil {
		return out, err
	}
	if hex.EncodeToString(fingerprint) != hex.EncodeToString(c.Fingerprint[:]) {
		return admission.Result{Reason: admission.IdempotencyConflict}, nil
	}
	if requestID != id {
		out, err = existing(ctx, tx, requestID, decision, reason, storedVersion, fingerprint)
		if err != nil {
			return out, err
		}
		if err = tx.Commit(ctx); err != nil {
			return admission.Result{}, err
		}
		return out, nil
	}
	if err = audit(ctx, tx, c, id, nil, "REQUEST_CREATED", "REQUEST_CREATED", time.Time{}); err != nil {
		return out, err
	}
	out = admission.Result{RequestID: id, PolicyVersion: c.Decision.PolicyVersion, Fingerprint: c.Fingerprint}
	if !c.Decision.Approved {
		out.Reason = admission.StaticPolicyDenied
		out.PolicyReason = c.Decision.Reason
		if err = finishDenied(ctx, tx, c, id, string(out.Reason), string(out.PolicyReason)); err != nil {
			return out, err
		}
		if err = tx.Commit(ctx); err != nil {
			return admission.Result{}, err
		}
		return out, nil
	}
	_, err = tx.Exec(ctx, `INSERT INTO service_controls(chain_id,updated_at) VALUES($1::numeric,$2) ON CONFLICT DO NOTHING`, chain, c.Now)
	if err != nil {
		return out, err
	}
	var disabled bool
	err = tx.QueryRow(ctx, `SELECT issuance_disabled FROM service_controls WHERE chain_id=$1::numeric FOR SHARE`, chain).Scan(&disabled)
	if err != nil {
		return out, err
	}
	if disabled {
		out.Reason = admission.EmergencyDisabled
		if err = finishDenied(ctx, tx, c, id, string(out.Reason), ""); err != nil {
			return out, err
		}
		if err = tx.Commit(ctx); err != nil {
			return admission.Result{}, err
		}
		return out, nil
	}
	// All rows are initialized and locked in this order in every admission transaction.
	specs := periodSpecs(c)
	var balances [3]periodBalance
	for i, s := range specs {
		balances[i], err = lockPeriod(ctx, tx, s, c.Now)
		if err != nil {
			return out, err
		}
	}
	amount := c.Decision.EstimatedUpperBound.Uint256
	for i, b := range balances {
		used := new(big.Int).Add(b.held, b.consumed)
		used.Add(used, amount.Big())
		if used.Cmp(b.limit) > 0 {
			switch i {
			case 0:
				out.Reason = admission.GlobalBudgetExhausted
			case 1:
				out.Reason = admission.ChainBudgetExhausted
			case 2:
				out.Reason = admission.QuotaExhausted
			}
			break
		}
		if i == 2 && b.admitted >= specs[i].limitCount {
			out.Reason = admission.QuotaExhausted
			break
		}
	}
	if out.Reason != "" {
		if err = finishDenied(ctx, tx, c, id, string(out.Reason), ""); err != nil {
			return out, err
		}
		if err = tx.Commit(ctx); err != nil {
			return admission.Result{}, err
		}
		return out, nil
	}
	for _, s := range specs {
		_, err = tx.Exec(ctx, `UPDATE budget_periods SET held_wei=held_wei+$1::numeric,held_count=held_count+1,admitted_count=admitted_count+$2,updated_at=$3 WHERE chain_id=$4::numeric AND period_start=$5 AND scope=$6 AND subject=$7`, amount.String(), boolInt(s.scope == "SENDER"), c.Now, s.chain, s.day, s.scope, s.subject)
		if err != nil {
			return out, err
		}
	}
	sponsorship, err := randomID()
	if err != nil {
		return out, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO sponsorship_reservations(sponsorship_id,request_id,chain_id,sender,period_start,reserved_cost_wei,status,valid_after,valid_until,created_at) VALUES($1,$2,$3::numeric,$4,$5,$6::numeric,'RESERVED',$7,$8,$9)`, sponsorship, id, chain, sender[:], specs[0].day, amount.String(), c.Decision.ValidAfter, c.Decision.ValidUntil, c.Now)
	if err != nil {
		return out, err
	}
	_, err = tx.Exec(ctx, `UPDATE sponsorship_requests SET decision='APPROVED',reason=$1,updated_at=$2 WHERE request_id=$3`, string(admission.Approved), c.Now, id)
	if err != nil {
		return out, err
	}
	if err = audit(ctx, tx, c, id, sponsorship, "RESERVATION_APPROVED", string(admission.Approved), c.Decision.ValidUntil); err != nil {
		return out, err
	}
	out.Approved = true
	out.Reason = admission.Approved
	out.SponsorshipID = hex.EncodeToString(sponsorship)
	out.EstimatedUpperBoundWei = amount.String()
	remaining := new(big.Int).Sub(balances[0].limit, new(big.Int).Add(balances[0].held, balances[0].consumed))
	remaining.Sub(remaining, amount.Big())
	out.GlobalBudgetRemainingWei = remaining.String()
	out.ValidAfter = c.Decision.ValidAfter
	out.ValidUntil = c.Decision.ValidUntil
	if err = tx.Commit(ctx); err != nil {
		return admission.Result{}, err
	}
	return out, nil
}
func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

type periodSpec struct {
	chain, day, scope string
	subject           []byte
	limit             policy.Uint256
	limitCount        int64
}
type periodBalance struct {
	limit, held, consumed *big.Int
	admitted              int64
}

func periodSpecs(c admission.Candidate) [3]periodSpec {
	day := c.Now.UTC().Format("2006-01-02")
	chain := c.Request.ChainID().String()
	sender := c.Request.Sender()
	zero := make([]byte, 20)
	limits := c.Limits.Chains[c.Request.ChainID()]
	return [3]periodSpec{{"0", day, "ALL_CHAINS", zero, c.Limits.Global, 0}, {chain, day, "GLOBAL", zero, limits.Daily, 0}, {chain, day, "SENDER", sender[:], limits.SenderDaily, limits.SenderCount}}
}
func lockPeriod(ctx context.Context, tx pgx.Tx, s periodSpec, now time.Time) (periodBalance, error) {
	var count any
	if s.scope == "SENDER" {
		count = s.limitCount
	}
	_, err := tx.Exec(ctx, `INSERT INTO budget_periods(chain_id,period_start,scope,subject,limit_wei,limit_count,updated_at) VALUES($1::numeric,$2,$3,$4,$5::numeric,$6,$7) ON CONFLICT DO NOTHING`, s.chain, s.day, s.scope, s.subject, s.limit.String(), count, now)
	if err != nil {
		return periodBalance{}, err
	}
	var limit, held, consumed string
	var admitted int64
	err = tx.QueryRow(ctx, `SELECT limit_wei::text,held_wei::text,consumed_wei::text,admitted_count FROM budget_periods WHERE chain_id=$1::numeric AND period_start=$2 AND scope=$3 AND subject=$4 FOR UPDATE`, s.chain, s.day, s.scope, s.subject).Scan(&limit, &held, &consumed, &admitted)
	if err != nil {
		return periodBalance{}, err
	}
	_, err = tx.Exec(ctx, `UPDATE budget_periods SET limit_wei=$1::numeric,limit_count=$2,updated_at=$3 WHERE chain_id=$4::numeric AND period_start=$5 AND scope=$6 AND subject=$7`, s.limit.String(), count, now, s.chain, s.day, s.scope, s.subject)
	if err != nil {
		return periodBalance{}, err
	}
	parse := func(raw string) *big.Int { v, _ := new(big.Int).SetString(raw, 10); return v }
	return periodBalance{parse(s.limit.String()), parse(held), parse(consumed), admitted}, nil
}
func finishDenied(ctx context.Context, tx pgx.Tx, c admission.Candidate, id, reason, policyReason string) error {
	_, err := tx.Exec(ctx, `UPDATE sponsorship_requests SET decision='DENIED',reason=$1,updated_at=$2 WHERE request_id=$3`, reason, c.Now, id)
	if err != nil {
		return err
	}
	event := "ADMISSION_DENIED"
	if reason == string(admission.StaticPolicyDenied) {
		event = "STATIC_POLICY_DENIED"
		reason = policyReason
	}
	return audit(ctx, tx, c, id, nil, event, reason, time.Time{})
}
func existing(ctx context.Context, tx pgx.Tx, id, decision, reason string, version int64, fingerprint []byte) (admission.Result, error) {
	out := admission.Result{RequestID: id, PolicyVersion: policy.PolicyVersion(version), Replayed: true}
	copy(out.Fingerprint[:], fingerprint)
	if decision == "DENIED" {
		out.Reason = admission.Reason(reason)
		if out.Reason == admission.StaticPolicyDenied {
			var policyReason string
			err := tx.QueryRow(ctx, `SELECT reason FROM audit_events WHERE request_id=$1 AND event_type='STATIC_POLICY_DENIED' LIMIT 1`, id).Scan(&policyReason)
			if err != nil {
				return out, err
			}
			out.PolicyReason = policy.Reason(policyReason)
		}
		return out, nil
	}
	if decision != "APPROVED" {
		return out, errors.New("committed pending request")
	}
	var sid []byte
	var amount string
	var status string
	err := tx.QueryRow(ctx, `SELECT sponsorship_id,reserved_cost_wei::text,status,valid_after,valid_until FROM sponsorship_reservations WHERE request_id=$1`, id).Scan(&sid, &amount, &status, &out.ValidAfter, &out.ValidUntil)
	if err != nil {
		return out, err
	}
	out.SponsorshipID = hex.EncodeToString(sid)
	out.EstimatedUpperBoundWei = amount
	out.Approved = status == "RESERVED" || status == "CONSUMED"
	out.Reason = admission.Approved
	if status == "EXPIRED" {
		out.Reason = admission.ReservationExpired
		out.Approved = false
	}
	if status == "RELEASED" {
		out.Reason = admission.ReservationStateConflict
		out.Approved = false
	}
	return out, nil
}
func audit(ctx context.Context, tx pgx.Tx, c admission.Candidate, id string, sid []byte, event, reason string, expiry time.Time) error {
	eid, err := uuid()
	if err != nil {
		return err
	}
	call := c.Request.Call()
	entry := c.Request.EntryPoint()
	sender := c.Request.Sender()
	var exp any
	if !expiry.IsZero() {
		exp = expiry
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(event_id,event_key,request_id,sponsorship_id,policy_version,chain_id,entry_point,event_type,decision,reason,sender,target,selector,digest,request_fingerprint,expires_at,occurred_at) VALUES($1,$2,$3,$4,$5,$6::numeric,$7,$8,$9,$10,$11,$12,$13,NULL,$14,$15,$16)`, eid, id+":"+event, id, sid, int64(c.Decision.PolicyVersion), c.Request.ChainID().String(), entry[:], event, event, reason, sender[:], call.Target[:], call.Selector[:], c.Fingerprint[:], exp, c.Now)
	return err
}
