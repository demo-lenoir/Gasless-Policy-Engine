package store

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// SponsorshipView is the public projection of one durable request. Economic
// amounts remain decimal strings because JSON numbers cannot represent Wei.
type SponsorshipView struct {
	RequestID        string     `json:"request_id"`
	SponsorshipID    string     `json:"sponsorship_id"`
	Decision         string     `json:"decision"`
	Reason           string     `json:"reason"`
	PolicyVersion    int64      `json:"policy_version"`
	ReservationState string     `json:"reservation_state"`
	IssuanceState    string     `json:"issuance_state"`
	OutcomeState     string     `json:"outcome_state"`
	ValidAfter       time.Time  `json:"valid_after"`
	ValidUntil       time.Time  `json:"valid_until"`
	UserOpHash       string     `json:"user_op_hash,omitempty"`
	ExecutionSuccess *bool      `json:"execution_success,omitempty"`
	ActualGasCostWei string     `json:"actual_gas_cost_wei,omitempty"`
	BlockNumber      *int64     `json:"outcome_block_number,omitempty"`
	BlockHash        string     `json:"outcome_block_hash,omitempty"`
	FinalizedHead    *int64     `json:"finalized_head_number,omitempty"`
	SettledAt        *time.Time `json:"settled_at,omitempty"`
}

func (p *Postgres) ReadSponsorship(ctx context.Context, scope, id string) (*SponsorshipView, error) {
	if scope == "" || len(id) != 64 || strings.Trim(id, "0123456789abcdefABCDEF") != "" {
		return nil, errors.New("invalid sponsorship lookup")
	}
	raw, _ := hex.DecodeString(id)
	bounded, cancel := dbContext(ctx, p.timeout)
	defer cancel()
	var v SponsorshipView
	var hash, block []byte
	var actual *string
	var issued bool
	err := p.pool.QueryRow(bounded, `SELECT q.request_id::text,q.decision,q.reason,q.policy_version,r.status,r.signed_artifact IS NOT NULL,r.outcome_state,r.valid_after,r.valid_until,r.user_op_hash,r.execution_success,r.actual_cost_wei::text,r.outcome_block_number,r.outcome_block_hash,r.finalized_head_number,r.settled_at FROM sponsorship_reservations r JOIN sponsorship_requests q ON q.request_id=r.request_id WHERE r.sponsorship_id=$1 AND q.client_scope=$2`, raw, scope).Scan(&v.RequestID, &v.Decision, &v.Reason, &v.PolicyVersion, &v.ReservationState, &issued, &v.OutcomeState, &v.ValidAfter, &v.ValidUntil, &hash, &v.ExecutionSuccess, &actual, &v.BlockNumber, &block, &v.FinalizedHead, &v.SettledAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	v.SponsorshipID = "0x" + strings.ToLower(id)
	v.IssuanceState = "NOT_ISSUED"
	if issued {
		v.IssuanceState = "ISSUED"
	}
	if len(hash) == 32 {
		v.UserOpHash = "0x" + hex.EncodeToString(hash)
	}
	if len(block) == 32 {
		v.BlockHash = "0x" + hex.EncodeToString(block)
	}
	if actual != nil {
		v.ActualGasCostWei = *actual
	}
	return &v, nil
}

type OperationalState struct {
	OpenReservations  int64  `json:"open_reservations"`
	Consumed          int64  `json:"consumed"`
	Expired           int64  `json:"expired"`
	BudgetRemaining   string `json:"global_budget_remaining_wei"`
	EmergencyDisabled bool   `json:"emergency_disabled"`
	AccountingValid   bool   `json:"accounting_valid"`
}

func (p *Postgres) ReadOperationalState(ctx context.Context, chain string, now time.Time) (OperationalState, error) {
	bounded, cancel := dbContext(ctx, p.timeout)
	defer cancel()
	var v OperationalState
	err := p.pool.QueryRow(bounded, `SELECT count(*) FILTER (WHERE status='RESERVED'),count(*) FILTER (WHERE status='CONSUMED'),count(*) FILTER (WHERE status='EXPIRED') FROM sponsorship_reservations WHERE chain_id=$1::numeric`, chain).Scan(&v.OpenReservations, &v.Consumed, &v.Expired)
	if err != nil {
		return v, err
	}
	err = p.pool.QueryRow(bounded, `SELECT (limit_wei-held_wei-consumed_wei)::text FROM budget_periods WHERE scope='ALL_CHAINS' AND chain_id=0 AND period_start=$1`, now.UTC().Format("2006-01-02")).Scan(&v.BudgetRemaining)
	if errors.Is(err, pgx.ErrNoRows) {
		v.BudgetRemaining = ""
	} else if err != nil {
		return v, err
	}
	err = p.pool.QueryRow(bounded, `SELECT issuance_disabled FROM service_controls WHERE chain_id=$1::numeric`, chain).Scan(&v.EmergencyDisabled)
	if errors.Is(err, pgx.ErrNoRows) {
		// The first admission initializes this row under the reservation transaction.
		// Its absence is safe only because that transaction still checks the control.
		v.EmergencyDisabled = false
	} else if err != nil {
		return v, err
	}
	err = p.pool.QueryRow(bounded, `SELECT NOT EXISTS(SELECT 1 FROM budget_periods WHERE held_wei<0 OR consumed_wei<0 OR held_wei+consumed_wei>limit_wei) AND NOT EXISTS(SELECT 1 FROM sponsorship_reservations r WHERE r.status='CONSUMED' AND r.signed_artifact IS NOT NULL AND NOT EXISTS(SELECT 1 FROM actual_spend_ledger l WHERE l.sponsorship_id=r.sponsorship_id))`).Scan(&v.AccountingValid)
	return v, err
}
