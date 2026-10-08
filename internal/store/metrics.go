package store

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"time"
)

type LedgerMetrics struct {
	ReservedCount           int64
	ActiveArtifacts         int64
	EstimatedSpendWei       string
	ActualSpendWei          string
	ReleasedWei             string
	DailyBudgetRemainingWei string
}

// ReadLedgerMetrics restores process-local gauges from the authoritative ledger.
func (p *Postgres) ReadLedgerMetrics(ctx context.Context, now time.Time) (LedgerMetrics, error) {
	bounded, cancel := dbContext(ctx, p.timeout)
	defer cancel()
	var out LedgerMetrics
	err := p.pool.QueryRow(bounded, `SELECT count(*) FILTER (WHERE status='RESERVED'),count(*) FILTER (WHERE status='RESERVED' AND signed_artifact IS NOT NULL AND valid_until>$1),COALESCE(sum(reserved_cost_wei),0)::text FROM sponsorship_reservations`, now.UTC()).Scan(&out.ReservedCount, &out.ActiveArtifacts, &out.EstimatedSpendWei)
	if err != nil {
		return LedgerMetrics{}, err
	}
	err = p.pool.QueryRow(bounded, `SELECT (SELECT COALESCE(sum(actual_wei),0)::text FROM actual_spend_ledger), ((SELECT COALESCE(sum(released_wei),0) FROM actual_spend_ledger)+(SELECT COALESCE(sum(reserved_cost_wei),0) FROM sponsorship_reservations WHERE status IN ('EXPIRED','RELEASED')))::text`).Scan(&out.ActualSpendWei, &out.ReleasedWei)
	if err != nil {
		return LedgerMetrics{}, err
	}
	err = p.pool.QueryRow(bounded, `SELECT (limit_wei-held_wei-consumed_wei)::text FROM budget_periods WHERE chain_id=0 AND period_start=$1 AND scope='ALL_CHAINS'`, now.UTC().Format("2006-01-02")).Scan(&out.DailyBudgetRemainingWei)
	if errors.Is(err, pgx.ErrNoRows) {
		out.DailyBudgetRemainingWei = ""
	} else if err != nil {
		return LedgerMetrics{}, err
	}
	return out, nil
}
