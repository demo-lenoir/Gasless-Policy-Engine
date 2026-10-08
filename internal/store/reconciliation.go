package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"math/big"
	"time"

	"github.com/demo-lenoir/gasless-policy-engine/internal/policy"
	"github.com/demo-lenoir/gasless-policy-engine/internal/reconcile"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/jackc/pgx/v5"
	"go.opentelemetry.io/otel"
)

func streamArgs(s reconcile.Stream) (string, []byte, string) {
	return s.ChainID.String(), s.EntryPoint[:], s.ID
}

func streamIdentity(s reconcile.Stream, entry, paymaster, code, genesis []byte, id string, confirmations, depth int64) error {
	var expectedCode, expectedGenesis []byte
	if s.ExpectedCodeHash != (common.Hash{}) {
		expectedCode = s.ExpectedCodeHash[:]
	}
	if s.ExpectedGenesisHash != (common.Hash{}) {
		expectedGenesis = s.ExpectedGenesisHash[:]
	}
	if !bytes.Equal(entry, s.EntryPoint[:]) || !bytes.Equal(paymaster, s.Paymaster[:]) || id != s.ID || confirmations != int64(s.Confirmations) || depth != int64(s.MaxReorgDepth) || !bytes.Equal(code, expectedCode) || !bytes.Equal(genesis, expectedGenesis) {
		return errors.New("reconciliation stream configuration differs from checkpoint")
	}
	return nil
}

func (p *Postgres) Checkpoint(ctx context.Context, s reconcile.Stream) (reconcile.Checkpoint, error) {
	bounded, cancel := dbContext(ctx, p.timeout)
	defer cancel()
	chain, _, _ := streamArgs(s)
	var c reconcile.Checkpoint
	var hash, entry, paymaster, code, genesis []byte
	var id string
	var number, confirmations, depth int64
	err := p.pool.QueryRow(bounded, `SELECT block_number,block_hash,block_time,state,entry_point,stream_id,paymaster,confirmations,max_reorg_depth,expected_code_hash,expected_genesis_hash FROM reconciliation_checkpoints WHERE chain_id=$1::numeric`, chain).Scan(&number, &hash, &c.Time, &c.State, &entry, &id, &paymaster, &confirmations, &depth, &code, &genesis)
	if errors.Is(err, pgx.ErrNoRows) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	if err = streamIdentity(s, entry, paymaster, code, genesis, id, confirmations, depth); err != nil {
		return reconcile.Checkpoint{}, err
	}
	c.Number = uint64(number)
	c.Hash = common.BytesToHash(hash)
	c.Exists = true
	return c, nil
}

func (p *Postgres) CheckpointAt(ctx context.Context, s reconcile.Stream, height uint64) (common.Hash, error) {
	bounded, cancel := dbContext(ctx, p.timeout)
	defer cancel()
	var hash []byte
	err := p.pool.QueryRow(bounded, `SELECT block_hash FROM reconciliation_blocks WHERE chain_id=$1::numeric AND block_number=$2 AND canonical`, s.ChainID.String(), int64(height)).Scan(&hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return common.Hash{}, nil
	}
	return common.BytesToHash(hash), err
}

func lockedCheckpoint(ctx context.Context, tx pgx.Tx, s reconcile.Stream) (reconcile.Checkpoint, error) {
	chain, _, _ := streamArgs(s)
	var c reconcile.Checkpoint
	var hash, entry, paymaster, code, genesis []byte
	var id string
	var number, confirmations, depth int64
	err := tx.QueryRow(ctx, `SELECT block_number,block_hash,block_time,state,entry_point,stream_id,paymaster,confirmations,max_reorg_depth,expected_code_hash,expected_genesis_hash FROM reconciliation_checkpoints WHERE chain_id=$1::numeric FOR UPDATE`, chain).Scan(&number, &hash, &c.Time, &c.State, &entry, &id, &paymaster, &confirmations, &depth, &code, &genesis)
	if errors.Is(err, pgx.ErrNoRows) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	if err = streamIdentity(s, entry, paymaster, code, genesis, id, confirmations, depth); err != nil {
		return reconcile.Checkpoint{}, err
	}
	c.Number = uint64(number)
	c.Hash = common.BytesToHash(hash)
	c.Exists = true
	return c, nil
}

func sameCheckpoint(a, b reconcile.Checkpoint) bool {
	return a.Exists == b.Exists && (!a.Exists || a.Number == b.Number && a.Hash == b.Hash && a.State == b.State)
}

func (p *Postgres) ApplyBlock(ctx context.Context, s reconcile.Stream, expected reconcile.Checkpoint, h *types.Header, events []reconcile.Event, now time.Time) error {
	if h == nil || !h.Number.IsUint64() || h.Number.Uint64() > math.MaxInt64 || h.Time > math.MaxInt64 || now.IsZero() {
		return errors.New("invalid canonical block")
	}
	bounded, cancel := dbContext(ctx, p.timeout)
	defer cancel()
	tx, err := p.pool.Begin(bounded)
	if err != nil {
		return err
	}
	defer tx.Rollback(bounded)
	// The stream row serializes workers before block and reservation rows are touched.
	if !expected.Exists {
		var expectedCode, expectedGenesis []byte
		if s.ExpectedCodeHash != (common.Hash{}) {
			expectedCode = s.ExpectedCodeHash[:]
		}
		if s.ExpectedGenesisHash != (common.Hash{}) {
			expectedGenesis = s.ExpectedGenesisHash[:]
		}
		_, err = tx.Exec(bounded, `INSERT INTO reconciliation_checkpoints(chain_id,entry_point,stream_id,paymaster,confirmations,max_reorg_depth,expected_code_hash,expected_genesis_hash,block_number,block_hash,block_time,updated_at) VALUES($1::numeric,$2,$3,$4,$5,$6,$7,$8,0,$9,to_timestamp(0),$10) ON CONFLICT DO NOTHING`, s.ChainID.String(), s.EntryPoint[:], s.ID, s.Paymaster[:], int64(s.Confirmations), int64(s.MaxReorgDepth), expectedCode, expectedGenesis, make([]byte, 32), now)
		if err != nil {
			return err
		}
	}
	current, err := lockedCheckpoint(bounded, tx, s)
	if err != nil {
		return err
	}
	if expected.Exists {
		if !sameCheckpoint(current, expected) || (current.State != "HEALTHY" && !(s.Recovering && current.State == "MANUAL_INTERVENTION")) || h.Number.Uint64() != current.Number+1 || h.ParentHash != current.Hash {
			return reconcile.ErrStaleCheckpoint
		}
	} else if current.Number != 0 || current.Hash != (common.Hash{}) || h.Number.Uint64() != 0 {
		return reconcile.ErrStaleCheckpoint
	}
	blockHash := h.Hash()
	blockTime := time.Unix(int64(h.Time), 0).UTC()
	_, err = tx.Exec(bounded, `INSERT INTO reconciliation_blocks(chain_id,block_hash,block_number,parent_hash,block_time,canonical,observed_at) VALUES($1::numeric,$2,$3,$4,$5,TRUE,$6) ON CONFLICT(chain_id,block_hash) DO UPDATE SET canonical=TRUE`, s.ChainID.String(), blockHash[:], h.Number.Int64(), h.ParentHash[:], blockTime, now)
	if err != nil {
		return err
	}
	for _, e := range events {
		if e.BlockHash != blockHash || e.BlockNumber != h.Number.Uint64() || uint64(e.LogIndex) > math.MaxInt64 || e.Paymaster != common.Address(s.Paymaster) || e.Nonce == nil || e.Nonce.Sign() < 0 || e.Nonce.BitLen() > 256 || e.ActualGasCost == nil || e.ActualGasCost.Sign() < 0 || e.ActualGasCost.BitLen() > 256 || e.ActualGasUsed == nil || e.ActualGasUsed.Sign() < 0 || e.ActualGasUsed.BitLen() > 256 {
			return errors.New("invalid event block or quantity")
		}
		var sponsor []byte
		var sender, paymaster, entry []byte
		var nonce, status string
		err = tx.QueryRow(bounded, `SELECT r.sponsorship_id,r.sender,r.paymaster_address,i.entry_point,q.request_payload->>'nonce',r.status FROM sponsorship_reservations r JOIN sponsorship_requests q ON q.request_id=r.request_id JOIN issuance_profiles i ON i.policy_version=q.policy_version AND i.chain_id=q.chain_id WHERE r.chain_id=$1::numeric AND r.user_op_hash=$2`, s.ChainID.String(), e.UserOpHash[:]).Scan(&sponsor, &sender, &paymaster, &entry, &nonce, &status)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if err == nil && (!bytes.Equal(sender, e.Sender[:]) || !bytes.Equal(paymaster, e.Paymaster[:]) || !bytes.Equal(entry, s.EntryPoint[:]) || nonce != e.Nonce.String()) {
			if err = markAnomalyLocked(bounded, tx, s, sponsor, "CORRELATION_CONFLICT", now); err != nil {
				return err
			}
			if err = tx.Commit(bounded); err != nil {
				return err
			}
			return reconcile.ErrManualIntervention
		}
		if errors.Is(err, pgx.ErrNoRows) {
			sponsor = nil
		}
		tag, insertErr := tx.Exec(bounded, `INSERT INTO userop_observations(chain_id,block_hash,transaction_hash,log_index,block_number,entry_point,user_op_hash,sponsorship_id,sender,paymaster,nonce,execution_success,actual_gas_cost_wei,actual_gas_used,canonical,observed_at) VALUES($1::numeric,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::numeric,$12,$13::numeric,$14::numeric,TRUE,$15) ON CONFLICT(chain_id,block_hash,transaction_hash,log_index) DO UPDATE SET canonical=TRUE WHERE userop_observations.user_op_hash=EXCLUDED.user_op_hash AND userop_observations.sponsorship_id IS NOT DISTINCT FROM EXCLUDED.sponsorship_id AND userop_observations.sender=EXCLUDED.sender AND userop_observations.paymaster=EXCLUDED.paymaster AND userop_observations.nonce=EXCLUDED.nonce AND userop_observations.execution_success=EXCLUDED.execution_success AND userop_observations.actual_gas_cost_wei=EXCLUDED.actual_gas_cost_wei AND userop_observations.actual_gas_used=EXCLUDED.actual_gas_used`, s.ChainID.String(), blockHash[:], e.TxHash[:], int64(e.LogIndex), int64(e.BlockNumber), s.EntryPoint[:], e.UserOpHash[:], sponsor, e.Sender[:], e.Paymaster[:], e.Nonce.String(), e.Success, e.ActualGasCost.String(), e.ActualGasUsed.String(), now)
		if insertErr != nil {
			return insertErr
		}
		if tag.RowsAffected() != 1 {
			if err = markAnomalyLocked(bounded, tx, s, sponsor, "CONFLICTING_LOG_IDENTITY", now); err != nil {
				return err
			}
			if err = tx.Commit(bounded); err != nil {
				return err
			}
			return reconcile.ErrManualIntervention
		}
		if sponsor != nil {
			if status != "RESERVED" {
				if err = markAnomalyLocked(bounded, tx, s, sponsor, "EVENT_AFTER_TERMINAL_SETTLEMENT", now); err != nil {
					return err
				}
				if err = tx.Commit(bounded); err != nil {
					return err
				}
				return reconcile.ErrManualIntervention
			}
			_, err = tx.Exec(bounded, `UPDATE sponsorship_reservations SET outcome_state='OBSERVED',outcome_block_number=$1,outcome_block_hash=$2,outcome_tx_hash=$3,outcome_log_index=$4,execution_success=$5 WHERE sponsorship_id=$6 AND status='RESERVED'`, int64(e.BlockNumber), blockHash[:], e.TxHash[:], int64(e.LogIndex), e.Success, sponsor)
			if err != nil {
				return err
			}
			if err = auditReconciliation(bounded, tx, sponsor, "USEROP_OBSERVED", blockHash.Hex(), now); err != nil {
				return err
			}
		}
	}
	_, err = tx.Exec(bounded, `UPDATE reconciliation_checkpoints SET block_number=$1,block_hash=$2,block_time=$3,updated_at=$4 WHERE chain_id=$5::numeric AND entry_point=$6 AND stream_id=$7`, h.Number.Int64(), blockHash[:], blockTime, now, s.ChainID.String(), s.EntryPoint[:], s.ID)
	if err != nil {
		return err
	}
	return tx.Commit(bounded)
}

func auditReconciliation(ctx context.Context, tx pgx.Tx, sponsor []byte, event, keySuffix string, now time.Time) error {
	id, err := uuid()
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(event_id,event_key,request_id,sponsorship_id,policy_version,chain_id,entry_point,paymaster,event_type,decision,reason,sender,target,selector,digest,request_fingerprint,expires_at,occurred_at,details)
SELECT $1,q.request_id::text||':'||$2||':'||$3,q.request_id,r.sponsorship_id,q.policy_version,q.chain_id,decode(substr(q.request_payload->>'entry_point',3),'hex'),r.paymaster_address,$2,$2,$2,q.sender,q.target,q.selector,r.typed_digest,q.request_fingerprint,r.valid_until,$4,jsonb_build_object('evidence',$3,'user_op_hash',encode(r.user_op_hash,'hex'),'actual_cost_wei',r.actual_cost_wei::text,'execution_success',r.execution_success,'outcome_block_number',r.outcome_block_number) FROM sponsorship_reservations r JOIN sponsorship_requests q ON q.request_id=r.request_id WHERE r.sponsorship_id=$5 ON CONFLICT(event_key) DO NOTHING`, id, event, keySuffix, now, sponsor)
	return err
}

func markAnomalyLocked(ctx context.Context, tx pgx.Tx, s reconcile.Stream, sponsor []byte, code string, now time.Time) error {
	id, err := uuid()
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO reconciliation_anomalies(anomaly_id,chain_id,entry_point,sponsorship_id,code,observed_at) VALUES($1,$2::numeric,$3,$4,$5,$6)`, id, s.ChainID.String(), s.EntryPoint[:], sponsor, code, now)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE reconciliation_checkpoints SET state='MANUAL_INTERVENTION',anomaly=$1,updated_at=$2 WHERE chain_id=$3::numeric AND entry_point=$4 AND stream_id=$5`, code, now, s.ChainID.String(), s.EntryPoint[:], s.ID)
	if err != nil {
		return err
	}
	if sponsor != nil {
		_, err = tx.Exec(ctx, `UPDATE sponsorship_reservations SET outcome_state='MANUAL_INTERVENTION' WHERE sponsorship_id=$1 AND status='RESERVED'`, sponsor)
		if err == nil {
			err = auditReconciliation(ctx, tx, sponsor, "SETTLEMENT_ANOMALY", code, now)
		}
	}
	return err
}

func (p *Postgres) MarkManual(ctx context.Context, s reconcile.Stream, code string, now time.Time) error {
	bounded, cancel := dbContext(ctx, p.timeout)
	defer cancel()
	tx, err := p.pool.Begin(bounded)
	if err != nil {
		return err
	}
	defer tx.Rollback(bounded)
	if _, err = lockedCheckpoint(bounded, tx, s); err != nil {
		return err
	}
	if err = markAnomalyLocked(bounded, tx, s, nil, code, now); err != nil {
		return err
	}
	return tx.Commit(bounded)
}

func (p *Postgres) RollbackTo(ctx context.Context, s reconcile.Stream, expected reconcile.Checkpoint, height uint64, ancestor common.Hash, now time.Time) error {
	bounded, cancel := dbContext(ctx, p.timeout)
	defer cancel()
	tx, err := p.pool.Begin(bounded)
	if err != nil {
		return err
	}
	defer tx.Rollback(bounded)
	current, err := lockedCheckpoint(bounded, tx, s)
	if err != nil {
		return err
	}
	if !sameCheckpoint(current, expected) {
		return reconcile.ErrStaleCheckpoint
	}
	var stored []byte
	var blockTime time.Time
	err = tx.QueryRow(bounded, `SELECT block_hash,block_time FROM reconciliation_blocks WHERE chain_id=$1::numeric AND block_number=$2 AND canonical`, s.ChainID.String(), int64(height)).Scan(&stored, &blockTime)
	if err != nil {
		return err
	}
	if !bytes.Equal(stored, ancestor[:]) {
		return reconcile.ErrStaleCheckpoint
	}
	rows, err := tx.Query(bounded, `SELECT DISTINCT r.sponsorship_id,r.status FROM sponsorship_reservations r JOIN userop_observations o ON o.sponsorship_id=r.sponsorship_id WHERE o.chain_id=$1::numeric AND o.canonical AND o.block_number>$2 ORDER BY r.sponsorship_id`, s.ChainID.String(), int64(height))
	if err != nil {
		return err
	}
	type affected struct {
		id     []byte
		status string
	}
	var items []affected
	for rows.Next() {
		var a affected
		if err = rows.Scan(&a.id, &a.status); err != nil {
			break
		}
		items = append(items, a)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return err
	}
	for _, a := range items {
		if a.status != "RESERVED" {
			if err = markAnomalyLocked(bounded, tx, s, a.id, "TERMINAL_REORG", now); err != nil {
				return err
			}
			if err = tx.Commit(bounded); err != nil {
				return err
			}
			return reconcile.ErrManualIntervention
		}
	}
	var expiredID []byte
	err = tx.QueryRow(bounded, `SELECT sponsorship_id FROM sponsorship_reservations WHERE chain_id=$1::numeric AND status='EXPIRED' AND outcome_state='EXPIRED_UNUSED' AND outcome_block_number>$2 LIMIT 1`, s.ChainID.String(), int64(height)).Scan(&expiredID)
	if err == nil {
		if err = markAnomalyLocked(bounded, tx, s, expiredID, "TERMINAL_EXPIRY_REORG", now); err != nil {
			return err
		}
		if err = tx.Commit(bounded); err != nil {
			return err
		}
		return reconcile.ErrManualIntervention
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	_, err = tx.Exec(bounded, `UPDATE userop_observations SET canonical=FALSE WHERE chain_id=$1::numeric AND canonical AND block_number>$2`, s.ChainID.String(), int64(height))
	if err != nil {
		return err
	}
	_, err = tx.Exec(bounded, `UPDATE reconciliation_blocks SET canonical=FALSE WHERE chain_id=$1::numeric AND canonical AND block_number>$2`, s.ChainID.String(), int64(height))
	if err != nil {
		return err
	}
	for _, a := range items {
		_, err = tx.Exec(bounded, `UPDATE sponsorship_reservations SET outcome_state='REORGED' WHERE sponsorship_id=$1 AND status='RESERVED'`, a.id)
		if err != nil {
			return err
		}
		if err = auditReconciliation(bounded, tx, a.id, "USEROP_REORGED", expected.Hash.Hex(), now); err != nil {
			return err
		}
	}
	_, err = tx.Exec(bounded, `UPDATE reconciliation_checkpoints SET block_number=$1,block_hash=$2,block_time=$3,updated_at=$4 WHERE chain_id=$5::numeric AND entry_point=$6 AND stream_id=$7`, int64(height), ancestor[:], blockTime, now, s.ChainID.String(), s.EntryPoint[:], s.ID)
	if err != nil {
		return err
	}
	return tx.Commit(bounded)
}

func (p *Postgres) Readiness(ctx context.Context, s reconcile.Stream) error {
	c, err := p.Checkpoint(ctx, s)
	if err != nil {
		return err
	}
	if !c.Exists || c.State != "HEALTHY" {
		return reconcile.ErrManualIntervention
	}
	return nil
}

func amount(raw string) (*big.Int, error) {
	n, ok := new(big.Int).SetString(raw, 10)
	if !ok || n.Sign() < 0 {
		return nil, fmt.Errorf("invalid stored Wei amount")
	}
	return n, nil
}

// Settle holds the checkpoint before reservation and budget rows. It never reads RPC inside the transaction.
func (p *Postgres) Settle(ctx context.Context, s reconcile.Stream, now time.Time, limit int) (int, error) {
	ctx, span := otel.Tracer("gasless/store").Start(ctx, "reconciliation.settlement_transaction")
	defer span.End()
	if now.IsZero() || limit < 1 || limit > 1000 {
		return 0, errors.New("invalid settlement batch")
	}
	bounded, cancel := dbContext(ctx, p.timeout)
	defer cancel()
	tx, err := p.pool.Begin(bounded)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(bounded)
	cp, err := lockedCheckpoint(bounded, tx, s)
	if err != nil {
		return 0, err
	}
	if !cp.Exists || cp.State != "HEALTHY" {
		return 0, reconcile.ErrManualIntervention
	}
	if cp.Number+1 < s.Confirmations {
		return 0, nil
	}
	finalHeight := cp.Number + 1 - s.Confirmations
	var finalTime time.Time
	var finalHash []byte
	err = tx.QueryRow(bounded, `SELECT block_time,block_hash FROM reconciliation_blocks WHERE chain_id=$1::numeric AND block_number=$2 AND canonical`, s.ChainID.String(), int64(finalHeight)).Scan(&finalTime, &finalHash)
	if err != nil {
		return 0, err
	}
	rows, err := tx.Query(bounded, `SELECT r.sponsorship_id FROM sponsorship_reservations r JOIN sponsorship_requests q ON q.request_id=r.request_id JOIN issuance_profiles i ON i.policy_version=q.policy_version AND i.chain_id=q.chain_id WHERE r.chain_id=$1::numeric AND i.entry_point=$2 AND i.paymaster_address=$3 AND r.status='RESERVED' AND r.signed_artifact IS NOT NULL AND r.user_op_hash IS NOT NULL AND (r.valid_until<$4 OR EXISTS(SELECT 1 FROM userop_observations o WHERE o.sponsorship_id=r.sponsorship_id AND o.canonical)) ORDER BY CASE WHEN r.valid_until<$4 OR EXISTS(SELECT 1 FROM userop_observations o WHERE o.sponsorship_id=r.sponsorship_id AND o.canonical AND o.block_number<=$5) THEN 0 ELSE 1 END,r.valid_until,r.sponsorship_id LIMIT $6 FOR UPDATE OF r SKIP LOCKED`, s.ChainID.String(), s.EntryPoint[:], s.Paymaster[:], finalTime, int64(finalHeight), limit)
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
	changed := 0
	var transitions []ReservationState
	for _, id := range ids {
		var reserved, status string
		var validUntil time.Time
		err = tx.QueryRow(bounded, `SELECT reserved_cost_wei::text,status,valid_until FROM sponsorship_reservations WHERE sponsorship_id=$1`, id).Scan(&reserved, &status, &validUntil)
		if err != nil {
			return 0, err
		}
		if status != "RESERVED" {
			continue
		}
		observations, err := tx.Query(bounded, `SELECT block_hash,transaction_hash,log_index,block_number,actual_gas_cost_wei::text,execution_success FROM userop_observations WHERE sponsorship_id=$1 AND canonical ORDER BY block_number,log_index LIMIT 2`, id)
		if err != nil {
			return 0, err
		}
		type observed struct {
			block, transaction []byte
			index, height      int64
			cost               string
			success            bool
		}
		var found []observed
		for observations.Next() {
			var o observed
			if err = observations.Scan(&o.block, &o.transaction, &o.index, &o.height, &o.cost, &o.success); err != nil {
				break
			}
			found = append(found, o)
		}
		if err == nil {
			err = observations.Err()
		}
		observations.Close()
		if err != nil {
			return 0, err
		}
		if len(found) > 1 {
			if err = markAnomalyLocked(bounded, tx, s, id, "CONFLICTING_CANONICAL_EVENTS", now); err != nil {
				return 0, err
			}
			break
		}
		if len(found) == 1 {
			o := found[0]
			if uint64(o.height) > finalHeight {
				_, err = tx.Exec(bounded, `UPDATE sponsorship_reservations SET outcome_state='CONFIRMING' WHERE sponsorship_id=$1 AND status='RESERVED'`, id)
				if err != nil {
					return 0, err
				}
				continue
			}
			cap, err := amount(reserved)
			if err != nil {
				return 0, err
			}
			cost, err := amount(o.cost)
			if err != nil {
				return 0, err
			}
			if cost.Cmp(cap) > 0 {
				_, err = tx.Exec(bounded, `UPDATE sponsorship_reservations SET actual_cost_wei=$1::numeric,outcome_state='MANUAL_INTERVENTION' WHERE sponsorship_id=$2`, o.cost, id)
				if err != nil {
					return 0, err
				}
				if err = markAnomalyLocked(bounded, tx, s, id, "ACTUAL_COST_OVERAGE", now); err != nil {
					return 0, err
				}
				if err = auditReconciliation(bounded, tx, id, "SETTLEMENT_OVERAGE", common.BytesToHash(o.block).Hex(), now); err != nil {
					return 0, err
				}
				break
			}
			parsed, err := policy.ParseUint256(o.cost)
			if err != nil {
				return 0, err
			}
			_, err = tx.Exec(bounded, `UPDATE sponsorship_reservations SET outcome_state='FINAL',outcome_block_number=$1,outcome_block_hash=$2,outcome_tx_hash=$3,outcome_log_index=$4,execution_success=$5,finalized_head_number=$6,settled_at=$7 WHERE sponsorship_id=$8`, o.height, o.block, o.transaction, o.index, o.success, int64(cp.Number), now, id)
			if err != nil {
				return 0, err
			}
			state, transitionErr := transitionLocked(bounded, tx, id, Consumed, &parsed, now, true)
			if transitionErr != nil {
				return 0, transitionErr
			}
			transitions = append(transitions, state)
			var userHash []byte
			err = tx.QueryRow(bounded, `SELECT user_op_hash FROM sponsorship_reservations WHERE sponsorship_id=$1`, id).Scan(&userHash)
			if err != nil {
				return 0, err
			}
			remainder := new(big.Int).Sub(cap, cost)
			_, err = tx.Exec(bounded, `INSERT INTO actual_spend_ledger(sponsorship_id,chain_id,user_op_hash,block_hash,block_number,transaction_hash,log_index,reserved_wei,actual_wei,released_wei,execution_success,finalized_head_number,settled_at) VALUES($1,$2::numeric,$3,$4,$5,$6,$7,$8::numeric,$9::numeric,$10::numeric,$11,$12,$13)`, id, s.ChainID.String(), userHash, o.block, o.height, o.transaction, o.index, reserved, o.cost, remainder.String(), o.success, int64(cp.Number), now)
			if err != nil {
				return 0, err
			}
			if err = auditReconciliation(bounded, tx, id, "USEROP_FINAL", common.BytesToHash(o.block).Hex(), now); err != nil {
				return 0, err
			}
			changed++
			continue
		}
		if !now.After(validUntil) || !finalTime.After(validUntil) {
			continue
		}
		_, err = tx.Exec(bounded, `UPDATE sponsorship_reservations SET outcome_state='EXPIRED_UNUSED',outcome_block_number=$1,outcome_block_hash=$2,finalized_head_number=$3,settled_at=$4 WHERE sponsorship_id=$5`, int64(finalHeight), finalHash, int64(cp.Number), now, id)
		if err != nil {
			return 0, err
		}
		state, transitionErr := transitionLocked(bounded, tx, id, Expired, nil, now, true)
		if transitionErr != nil {
			return 0, transitionErr
		}
		transitions = append(transitions, state)
		if err = auditReconciliation(bounded, tx, id, "AUTHORIZATION_EXPIRED_UNUSED", fmt.Sprintf("%d", finalHeight), now); err != nil {
			return 0, err
		}
		changed++
	}
	if err = tx.Commit(bounded); err != nil {
		return 0, err
	}
	if p.observer != nil {
		for _, state := range transitions {
			p.observer.ReservationTransition(state.Status, state.GlobalBudgetRemainingWei)
		}
	}
	return changed, nil
}
