package store

import (
	"context"
	"encoding/hex"
	"errors"
	"math/big"
	"time"

	"github.com/demo-lenoir/gasless-policy-engine/internal/admission"
	"github.com/demo-lenoir/gasless-policy-engine/internal/policy"
	"github.com/jackc/pgx/v5"
)

type Transition string

const (
	Released Transition = "RELEASED"
	Expired  Transition = "EXPIRED"
	Consumed Transition = "CONSUMED"
)

var ErrStateConflict = errors.New(string(admission.ReservationStateConflict))

type ReservationState struct {
	Status                   Transition
	Changed                  bool
	GlobalBudgetRemainingWei string
}

// TransitionReservation only returns economic holds from authorizations that were never issued.
func (p *Postgres) TransitionReservation(ctx context.Context, id string, to Transition, actual *policy.Uint256, now time.Time) (ReservationState, error) {
	if now.IsZero() || (to != Released && to != Expired && to != Consumed) {
		return ReservationState{}, errors.New("invalid transition input")
	}
	sid, err := hex.DecodeString(id)
	if err != nil || len(sid) != 32 {
		return ReservationState{}, errors.New("invalid sponsorship ID")
	}
	bounded, cancel := dbContext(ctx, p.timeout)
	defer cancel()
	tx, err := p.pool.Begin(bounded)
	if err != nil {
		return ReservationState{}, err
	}
	defer tx.Rollback(bounded)
	state, err := transitionLocked(bounded, tx, sid, to, actual, now.UTC(), false)
	if err != nil {
		return state, err
	}
	if err = tx.Commit(bounded); err != nil {
		return ReservationState{}, err
	}
	if state.Changed && p.observer != nil {
		p.observer.ReservationTransition(state.Status, state.GlobalBudgetRemainingWei)
	}
	return state, nil
}

type reservation struct {
	requestID, chain, day, cost, status string
	sender                              []byte
	validUntil                          time.Time
	issuedAt                            *time.Time
	artifactPresent                     bool
	actualCost                          *string
}

func transitionLocked(ctx context.Context, tx pgx.Tx, sid []byte, to Transition, actual *policy.Uint256, now time.Time, chainEvidence bool) (ReservationState, error) {
	var r reservation
	err := tx.QueryRow(ctx, `SELECT request_id::text,chain_id::text,period_start::text,sender,reserved_cost_wei::text,status,valid_until,issued_at,signed_artifact IS NOT NULL,actual_cost_wei::text FROM sponsorship_reservations WHERE sponsorship_id=$1 FOR UPDATE`, sid).Scan(&r.requestID, &r.chain, &r.day, &r.sender, &r.cost, &r.status, &r.validUntil, &r.issuedAt, &r.artifactPresent, &r.actualCost)
	if err != nil {
		return ReservationState{}, err
	}
	if r.status == string(to) {
		if to == Consumed && (actual == nil || r.actualCost == nil || *r.actualCost != actual.String()) {
			return ReservationState{}, ErrStateConflict
		}
		return ReservationState{Status: to}, nil
	}
	if r.status != "RESERVED" {
		return ReservationState{}, ErrStateConflict
	}
	if to == Expired && (now.Before(r.validUntil) || ((r.issuedAt != nil || r.artifactPresent) && !chainEvidence)) {
		return ReservationState{}, ErrStateConflict
	}
	if to == Consumed && r.artifactPresent && !chainEvidence {
		return ReservationState{}, ErrStateConflict
	}
	if to == Released && (r.issuedAt != nil || r.artifactPresent) {
		return ReservationState{}, ErrStateConflict
	}
	reserved, err := policy.ParseUint256(r.cost)
	if err != nil {
		return ReservationState{}, errors.New("invalid stored reservation amount")
	}
	if to == Consumed {
		if actual == nil || actual.Cmp(reserved) > 0 {
			return ReservationState{}, ErrStateConflict
		}
	} else if actual != nil {
		return ReservationState{}, ErrStateConflict
	}
	// Every transition locks all-chain, chain, then sender, as admission does.
	specs := [][3]any{{"0", "ALL_CHAINS", make([]byte, 20)}, {r.chain, "GLOBAL", make([]byte, 20)}, {r.chain, "SENDER", r.sender}}
	for _, s := range specs {
		var held string
		err = tx.QueryRow(ctx, `SELECT held_wei::text FROM budget_periods WHERE chain_id=$1::numeric AND period_start=$2::date AND scope=$3 AND subject=$4 FOR UPDATE`, s[0], r.day, s[1], s[2]).Scan(&held)
		if err != nil {
			return ReservationState{}, err
		}
		h, ok := new(big.Int).SetString(held, 10)
		if !ok {
			return ReservationState{}, errors.New("invalid held balance")
		}
		cost := reserved.Big()
		if h.Cmp(cost) < 0 {
			return ReservationState{}, errors.New("held balance below reservation")
		}
	}
	spent := "0"
	count := 0
	if to == Consumed {
		spent = actual.String()
		count = 1
	}
	remainingGlobal := ""
	for i, s := range specs {
		tag, e := tx.Exec(ctx, `UPDATE budget_periods SET held_wei=held_wei-$1::numeric,consumed_wei=consumed_wei+$2::numeric,held_count=held_count-1,consumed_count=consumed_count+$3,updated_at=$4 WHERE chain_id=$5::numeric AND period_start=$6::date AND scope=$7 AND subject=$8`, r.cost, spent, count, now, s[0], r.day, s[1], s[2])
		if e != nil {
			return ReservationState{}, e
		}
		if tag.RowsAffected() != 1 {
			return ReservationState{}, errors.New("missing accounting row")
		}
		if i == 0 {
			err = tx.QueryRow(ctx, `SELECT (limit_wei-held_wei-consumed_wei)::text FROM budget_periods WHERE chain_id=0 AND period_start=$1::date AND scope='ALL_CHAINS'`, r.day).Scan(&remainingGlobal)
			if err != nil {
				return ReservationState{}, err
			}
		}
	}
	var costValue any
	if to == Consumed {
		costValue = spent
	}
	_, err = tx.Exec(ctx, `UPDATE sponsorship_reservations SET status=$1,actual_cost_wei=$2::numeric,transitioned_at=$3 WHERE sponsorship_id=$4`, string(to), costValue, now, sid)
	if err != nil {
		return ReservationState{}, err
	}
	eventID, err := uuid()
	if err != nil {
		return ReservationState{}, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(event_id,event_key,request_id,sponsorship_id,policy_version,chain_id,entry_point,event_type,decision,reason,sender,target,selector,request_fingerprint,expires_at,occurred_at)
 SELECT $1,request_id::text||':'||$2,request_id,$3,policy_version,chain_id,(SELECT entry_point FROM audit_events WHERE request_id=$4 AND event_type='REQUEST_CREATED'),$2,$2,$2,sender,target,selector,request_fingerprint,$5,$6 FROM sponsorship_requests WHERE request_id=$4`, eventID, string(to), sid, r.requestID, r.validUntil, now)
	if err != nil {
		return ReservationState{}, err
	}
	return ReservationState{Status: to, Changed: true, GlobalBudgetRemainingWei: remainingGlobal}, nil
}

// ExpireReservations processes a bounded batch; concurrent workers skip locked rows.
func (p *Postgres) ExpireReservations(ctx context.Context, now time.Time, limit int) (int, error) {
	if now.IsZero() || limit < 1 || limit > 1000 {
		return 0, errors.New("invalid expiration batch")
	}
	bounded, cancel := dbContext(ctx, p.timeout)
	defer cancel()
	tx, err := p.pool.Begin(bounded)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(bounded)
	rows, err := tx.Query(bounded, `SELECT sponsorship_id FROM sponsorship_reservations WHERE status='RESERVED' AND issued_at IS NULL AND signed_artifact IS NULL AND valid_until<=$1 ORDER BY valid_until,sponsorship_id LIMIT $2 FOR UPDATE SKIP LOCKED`, now.UTC(), limit)
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
	states := make([]ReservationState, 0, len(ids))
	for _, id := range ids {
		var state ReservationState
		if state, err = transitionLocked(bounded, tx, id, Expired, nil, now.UTC(), false); err != nil {
			return 0, err
		}
		states = append(states, state)
	}
	if err = tx.Commit(bounded); err != nil {
		return 0, err
	}
	if p.observer != nil {
		for _, state := range states {
			p.observer.ReservationTransition(state.Status, state.GlobalBudgetRemainingWei)
		}
	}
	return len(ids), nil
}
