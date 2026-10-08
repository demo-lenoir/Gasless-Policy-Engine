package store

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/demo-lenoir/gasless-policy-engine/internal/reconcile"
	"github.com/ethereum/go-ethereum/common"
)

type RecoveryPlan struct {
	ChainID              string `json:"chain_id"`
	Checkpoint           uint64 `json:"checkpoint"`
	ProposedAncestor     uint64 `json:"proposed_ancestor"`
	AffectedBlocks       int64  `json:"affected_blocks"`
	AffectedSponsorships int64  `json:"affected_sponsorships"`
	TerminalConflicts    int64  `json:"terminal_conflicts"`
	Anomaly              string `json:"anomaly"`
	Safe                 bool   `json:"safe"`
}

// PlanRecovery is a read-only report. The caller must verify the proposed
// ancestor against the configured RPC before using the mutation operation.
func (p *Postgres) PlanRecovery(ctx context.Context, s reconcile.Stream, height uint64, remoteHash common.Hash) (RecoveryPlan, error) {
	bounded, cancel := dbContext(ctx, p.timeout)
	defer cancel()
	cp, err := p.Checkpoint(bounded, s)
	if err != nil {
		return RecoveryPlan{}, err
	}
	plan := RecoveryPlan{ChainID: s.ChainID.String(), Checkpoint: cp.Number, ProposedAncestor: height}
	if !cp.Exists || height > cp.Number {
		return plan, errors.New("recovery point outside saved chain")
	}
	var stored []byte
	err = p.pool.QueryRow(bounded, `SELECT block_hash FROM reconciliation_blocks WHERE chain_id=$1::numeric AND block_number=$2 AND canonical`, s.ChainID.String(), int64(height)).Scan(&stored)
	if err != nil {
		return plan, err
	}
	err = p.pool.QueryRow(bounded, `SELECT COALESCE(anomaly,'') FROM reconciliation_checkpoints WHERE chain_id=$1::numeric`, s.ChainID.String()).Scan(&plan.Anomaly)
	if err != nil {
		return plan, err
	}
	err = p.pool.QueryRow(bounded, `SELECT count(*) FROM reconciliation_blocks WHERE chain_id=$1::numeric AND canonical AND block_number>$2`, s.ChainID.String(), int64(height)).Scan(&plan.AffectedBlocks)
	if err != nil {
		return plan, err
	}
	err = p.pool.QueryRow(bounded, `SELECT count(DISTINCT sponsorship_id) FROM userop_observations WHERE chain_id=$1::numeric AND canonical AND sponsorship_id IS NOT NULL AND block_number>$2`, s.ChainID.String(), int64(height)).Scan(&plan.AffectedSponsorships)
	if err != nil {
		return plan, err
	}
	err = p.pool.QueryRow(bounded, `SELECT (SELECT count(DISTINCT r.sponsorship_id) FROM sponsorship_reservations r JOIN userop_observations o ON o.sponsorship_id=r.sponsorship_id WHERE o.chain_id=$1::numeric AND o.canonical AND o.block_number>$2 AND r.status<>'RESERVED')+(SELECT count(*) FROM sponsorship_reservations WHERE chain_id=$1::numeric AND status='EXPIRED' AND outcome_state='EXPIRED_UNUSED' AND outcome_block_number>$2)`, s.ChainID.String(), int64(height)).Scan(&plan.TerminalConflicts)
	if err != nil {
		return plan, err
	}
	var other int64
	err = p.pool.QueryRow(bounded, `SELECT count(*) FROM reconciliation_anomalies WHERE chain_id=$1::numeric AND resolved_at IS NULL AND code<>'DEEP_REORG'`, s.ChainID.String()).Scan(&other)
	if err != nil {
		return plan, err
	}
	plan.Safe = cp.State == "MANUAL_INTERVENTION" && plan.Anomaly == "DEEP_REORG" && bytes.Equal(stored, remoteHash[:]) && plan.TerminalConflicts == 0 && other == 0
	return plan, nil
}

// CompleteRecovery clears only a deep-reorg stop after the operator's bounded
// replay has converged to a header independently checked through the reader.
func (p *Postgres) CompleteRecovery(ctx context.Context, s reconcile.Stream, head uint64, hash common.Hash, now time.Time) error {
	if now.IsZero() {
		return errors.New("observation time required")
	}
	bounded, cancel := dbContext(ctx, p.timeout)
	defer cancel()
	tx, err := p.pool.Begin(bounded)
	if err != nil {
		return err
	}
	defer tx.Rollback(bounded)
	cp, err := lockedCheckpoint(bounded, tx, s)
	if err != nil {
		return err
	}
	var anomaly string
	err = tx.QueryRow(bounded, `SELECT COALESCE(anomaly,'') FROM reconciliation_checkpoints WHERE chain_id=$1::numeric`, s.ChainID.String()).Scan(&anomaly)
	if err != nil {
		return err
	}
	if !cp.Exists || cp.State != "MANUAL_INTERVENTION" || anomaly != "DEEP_REORG" || cp.Number != head || cp.Hash != hash {
		return reconcile.ErrManualIntervention
	}
	var unresolved int64
	err = tx.QueryRow(bounded, `SELECT count(*) FROM reconciliation_anomalies WHERE chain_id=$1::numeric AND resolved_at IS NULL AND code<>'DEEP_REORG'`, s.ChainID.String()).Scan(&unresolved)
	if err != nil {
		return err
	}
	if unresolved != 0 {
		return reconcile.ErrManualIntervention
	}
	_, err = tx.Exec(bounded, `UPDATE reconciliation_anomalies SET resolved_at=$1 WHERE chain_id=$2::numeric AND resolved_at IS NULL AND code='DEEP_REORG'`, now, s.ChainID.String())
	if err != nil {
		return err
	}
	_, err = tx.Exec(bounded, `UPDATE reconciliation_checkpoints SET state='HEALTHY',anomaly=NULL,updated_at=$1 WHERE chain_id=$2::numeric AND entry_point=$3 AND stream_id=$4`, now, s.ChainID.String(), s.EntryPoint[:], s.ID)
	if err != nil {
		return err
	}
	return tx.Commit(bounded)
}
