package store_test

import (
	"context"
	"encoding/hex"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/demo-lenoir/gasless-policy-engine/internal/issuance"
	"github.com/demo-lenoir/gasless-policy-engine/internal/policy"
	"github.com/demo-lenoir/gasless-policy-engine/internal/reconcile"
	"github.com/demo-lenoir/gasless-policy-engine/internal/store"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

type forkReader struct {
	mu     sync.RWMutex
	blocks []*types.Header
	logs   map[common.Hash][]types.Log
}

func newForkReader() *forkReader { return &forkReader{logs: map[common.Hash][]types.Log{}} }
func (f *forkReader) add(at time.Time, label string, logs []types.Log) common.Hash {
	f.mu.Lock()
	defer f.mu.Unlock()
	h := &types.Header{Number: big.NewInt(int64(len(f.blocks))), Time: uint64(at.Unix()), Extra: []byte(label), GasLimit: 30_000_000}
	if len(f.blocks) > 0 {
		h.ParentHash = f.blocks[len(f.blocks)-1].Hash()
	}
	f.blocks = append(f.blocks, h)
	hash := h.Hash()
	for i := range logs {
		logs[i].BlockHash = hash
		logs[i].BlockNumber = h.Number.Uint64()
		logs[i].Index = uint(i)
	}
	f.logs[hash] = logs
	return hash
}
func (f *forkReader) fork(height int)                           { f.mu.Lock(); defer f.mu.Unlock(); f.blocks = f.blocks[:height] }
func (f *forkReader) ChainID(context.Context) (*big.Int, error) { return big.NewInt(31337), nil }
func (f *forkReader) CodeAt(context.Context, common.Address, *big.Int) ([]byte, error) {
	return []byte{1}, nil
}
func (f *forkReader) HeaderByNumber(_ context.Context, n *big.Int) (*types.Header, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if n == nil {
		return f.blocks[len(f.blocks)-1], nil
	}
	if !n.IsInt64() || n.Int64() < 0 || n.Int64() >= int64(len(f.blocks)) {
		return nil, errors.New("block unavailable")
	}
	return f.blocks[int(n.Int64())], nil
}
func (f *forkReader) FilterLogs(_ context.Context, q ethereum.FilterQuery) ([]types.Log, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return append([]types.Log(nil), f.logs[*q.BlockHash]...), nil
}

func signedReservation(t *testing.T) (*store.Postgres, *forkReader, reconcile.Stream, []byte, common.Hash, string, time.Time) {
	t.Helper()
	p, admitter, input, cap := limits(t, 5, 5, 5)
	a := submit(t, admitter, key(1), input, now)
	if !a.Approved {
		t.Fatal(a.Reason)
	}
	signer, addr := signerFixture(t)
	svc := issuanceFixture(t, p, signer, addr, func() time.Time { return now.Add(time.Second) })
	if _, reason, err := svc.Issue(context.Background(), a.SponsorshipID); err != nil || reason != issuance.Issued {
		t.Fatalf("issue %s %v", reason, err)
	}
	id, _ := hex.DecodeString(a.SponsorshipID)
	var hash []byte
	if err := p.Pool().QueryRow(context.Background(), `SELECT user_op_hash FROM sponsorship_reservations WHERE sponsorship_id=$1`, id).Scan(&hash); err != nil || len(hash) != 32 {
		t.Fatalf("binding %v", err)
	}
	cfg := issuanceConfig(addr)
	stream := reconcile.Stream{ChainID: cfg.ChainID, EntryPoint: cfg.EntryPoint, Paymaster: cfg.Paymaster, ID: "test-v09", Confirmations: 3, MaxReorgDepth: 8, MaxBlocks: 100}
	f := newForkReader()
	f.add(now, "genesis", nil)
	return p, f, stream, id, common.BytesToHash(hash), cap, a.ValidUntil
}
func eventFor(s reconcile.Stream, hash common.Hash, success bool, cost string) types.Log {
	n, _ := new(big.Int).SetString(cost, 10)
	data := make([]byte, 128)
	big.NewInt(7).FillBytes(data[:32])
	if success {
		data[63] = 1
	}
	n.FillBytes(data[64:96])
	big.NewInt(100).FillBytes(data[96:128])
	return types.Log{Address: common.Address(s.EntryPoint), Topics: []common.Hash{reconcile.EventTopic, hash, common.BytesToHash(common.HexToAddress(testInput().Sender).Bytes()), common.BytesToHash(s.Paymaster[:])}, Data: data, TxHash: common.HexToHash("0x01")}
}
func statusOf(t *testing.T, p *store.Postgres, id []byte) (string, string, string) {
	t.Helper()
	var status, state, cost string
	err := p.Pool().QueryRow(context.Background(), `SELECT status,outcome_state,COALESCE(actual_cost_wei::text,'') FROM sponsorship_reservations WHERE sponsorship_id=$1`, id).Scan(&status, &state, &cost)
	if err != nil {
		t.Fatal(err)
	}
	return status, state, cost
}
func runWatcher(t *testing.T, p *store.Postgres, f *forkReader, s reconcile.Stream, at time.Time) {
	t.Helper()
	if err := (reconcile.Worker{Reader: f, Repository: p, Stream: s}).RunOnce(context.Background(), at); err != nil {
		t.Fatal(err)
	}
}

func TestReconciliationFinalityAndCost(t *testing.T) {
	for _, success := range []bool{true, false} {
		t.Run(map[bool]string{true: "success", false: "reverted"}[success], func(t *testing.T) {
			p, f, s, id, hash, cap, _ := signedReservation(t)
			cost := "1000000"
			f.add(now.Add(time.Second), "included", []types.Log{eventFor(s, hash, success, cost)})
			runWatcher(t, p, f, s, now.Add(2*time.Second))
			status, state, _ := statusOf(t, p, id)
			if status != "RESERVED" || state != "OBSERVED" {
				t.Fatalf("one confirmation %s/%s", status, state)
			}
			f.add(now.Add(2*time.Second), "second", nil)
			runWatcher(t, p, f, s, now.Add(3*time.Second))
			status, state, _ = statusOf(t, p, id)
			if status != "RESERVED" || state != "CONFIRMING" {
				t.Fatal("settled at two confirmations")
			}
			f.add(now.Add(3*time.Second), "third", nil)
			runWatcher(t, p, f, s, now.Add(4*time.Second))
			status, state, actual := statusOf(t, p, id)
			if status != "CONSUMED" || state != "FINAL" || actual != cost {
				t.Fatalf("three confirmations %s/%s/%s", status, state, actual)
			}
			var reserved, ledgerCost, released string
			var execution bool
			if err := p.Pool().QueryRow(context.Background(), `SELECT reserved_wei::text,actual_wei::text,released_wei::text,execution_success FROM actual_spend_ledger WHERE sponsorship_id=$1`, id).Scan(&reserved, &ledgerCost, &released, &execution); err != nil {
				t.Fatal(err)
			}
			c, _ := new(big.Int).SetString(cap, 10)
			a, _ := new(big.Int).SetString(cost, 10)
			r, _ := new(big.Int).SetString(released, 10)
			if reserved != cap || ledgerCost != cost || new(big.Int).Add(a, r).Cmp(c) != 0 || execution != success {
				t.Fatal("accounting conservation or execution status")
			}
			runWatcher(t, p, f, s, now.Add(5*time.Second))
			var count int
			if err := p.Pool().QueryRow(context.Background(), `SELECT count(*) FROM actual_spend_ledger WHERE sponsorship_id=$1`, id).Scan(&count); err != nil || count != 1 {
				t.Fatalf("duplicate spend %d %v", count, err)
			}
		})
	}
}

func TestReconciliationUnusedExpiry(t *testing.T) {
	p, f, s, id, _, cap, until := signedReservation(t)
	f.add(until.Add(-time.Second), "before", nil)
	f.add(until, "at", nil)
	f.add(until.Add(time.Second), "past", nil)
	runWatcher(t, p, f, s, until.Add(2*time.Second))
	status, _, _ := statusOf(t, p, id)
	if status != "RESERVED" {
		t.Fatal("expired without finality-covered chain time")
	}
	f.add(until.Add(2*time.Second), "confirm1", nil)
	f.add(until.Add(3*time.Second), "confirm2", nil)
	runWatcher(t, p, f, s, until.Add(4*time.Second))
	status, state, _ := statusOf(t, p, id)
	if status != "EXPIRED" || state != "EXPIRED_UNUSED" {
		t.Fatalf("unused %s/%s", status, state)
	}
	var held string
	if err := p.Pool().QueryRow(context.Background(), `SELECT held_wei::text FROM budget_periods WHERE chain_id=0 AND scope='ALL_CHAINS'`).Scan(&held); err != nil || held != "0" {
		t.Fatalf("held %s %v", held, err)
	}
	var reserved string
	if err := p.Pool().QueryRow(context.Background(), `SELECT reserved_cost_wei::text FROM sponsorship_reservations WHERE sponsorship_id=$1`, id).Scan(&reserved); err != nil || reserved != cap {
		t.Fatal("original amount lost")
	}
	runWatcher(t, p, f, s, until.Add(5*time.Second))
}

func TestReconciliationReorgAndReinclusion(t *testing.T) {
	p, f, s, id, hash, _, _ := signedReservation(t)
	f.add(now.Add(time.Second), "branch-a", []types.Log{eventFor(s, hash, true, "1000")})
	f.add(now.Add(2*time.Second), "branch-a-2", nil)
	runWatcher(t, p, f, s, now.Add(3*time.Second))
	f.fork(1)
	f.add(now.Add(time.Second), "branch-b", nil)
	f.add(now.Add(2*time.Second), "branch-b-2", nil)
	runWatcher(t, p, f, s, now.Add(3*time.Second))
	status, state, _ := statusOf(t, p, id)
	if status != "RESERVED" || state != "REORGED" {
		t.Fatalf("orphan %s/%s", status, state)
	}
	f.add(now.Add(3*time.Second), "reincluded", []types.Log{eventFor(s, hash, true, "1000")})
	f.add(now.Add(4*time.Second), "b4", nil)
	f.add(now.Add(5*time.Second), "b5", nil)
	runWatcher(t, p, f, s, now.Add(6*time.Second))
	status, state, _ = statusOf(t, p, id)
	if status != "CONSUMED" || state != "FINAL" {
		t.Fatalf("reinclusion %s/%s", status, state)
	}
	var count, canonical int
	if err := p.Pool().QueryRow(context.Background(), `SELECT count(*),count(*) FILTER(WHERE canonical) FROM userop_observations WHERE sponsorship_id=$1`, id).Scan(&count, &canonical); err != nil || count != 2 || canonical != 1 {
		t.Fatalf("fork evidence %d/%d %v", count, canonical, err)
	}
}

func TestReconciliationOverageAndDeepReorg(t *testing.T) {
	t.Run("overage", func(t *testing.T) {
		p, f, s, id, hash, cap, _ := signedReservation(t)
		upper, _ := new(big.Int).SetString(cap, 10)
		f.add(now.Add(time.Second), "overage", []types.Log{eventFor(s, hash, true, new(big.Int).Add(upper, big.NewInt(1)).String())})
		f.add(now.Add(2*time.Second), "next", nil)
		f.add(now.Add(3*time.Second), "final", nil)
		runWatcher(t, p, f, s, now.Add(4*time.Second))
		status, state, cost := statusOf(t, p, id)
		if status != "RESERVED" || state != "MANUAL_INTERVENTION" || cost != new(big.Int).Add(upper, big.NewInt(1)).String() {
			t.Fatalf("overage %s/%s/%s", status, state, cost)
		}
		if err := p.Readiness(context.Background(), s); err == nil {
			t.Fatal("overage readiness healthy")
		}
		var held string
		if err := p.Pool().QueryRow(context.Background(), `SELECT held_wei::text FROM budget_periods WHERE chain_id=0 AND scope='ALL_CHAINS'`).Scan(&held); err != nil || held != cap {
			t.Fatalf("overage hold %s %v", held, err)
		}
	})
	t.Run("deep", func(t *testing.T) {
		p, f, s, id, _, cap, _ := signedReservation(t)
		for i := 1; i <= 10; i++ {
			f.add(now.Add(time.Duration(i)*time.Second), "original", nil)
		}
		runWatcher(t, p, f, s, now.Add(11*time.Second))
		f.fork(1)
		for i := 1; i <= 10; i++ {
			f.add(now.Add(time.Duration(i)*time.Second), "replacement", nil)
		}
		err := (reconcile.Worker{Reader: f, Repository: p, Stream: s}).RunOnce(context.Background(), now.Add(12*time.Second))
		if !errors.Is(err, reconcile.ErrManualIntervention) {
			t.Fatalf("deep reorg: %v", err)
		}
		if err := p.Readiness(context.Background(), s); err == nil {
			t.Fatal("deep reorg readiness healthy")
		}
		status, _, _ := statusOf(t, p, id)
		if status != "RESERVED" {
			t.Fatal("deep reorg released hold")
		}
		var held string
		if err := p.Pool().QueryRow(context.Background(), `SELECT held_wei::text FROM budget_periods WHERE chain_id=0 AND scope='ALL_CHAINS'`).Scan(&held); err != nil || held != cap {
			t.Fatalf("deep hold %s %v", held, err)
		}
	})
}

func TestReconciliationTwoWorkersAndRestart(t *testing.T) {
	p, f, s, id, hash, _, until := signedReservation(t)
	f.add(until.Add(-time.Second), "included", []types.Log{eventFor(s, hash, false, "2000")})
	runWatcher(t, p, f, s, until)
	p2, err := store.Open(context.Background(), testDSN(t), 8, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer p2.Close()
	f.add(until.Add(time.Second), "after", nil)
	f.add(until.Add(2*time.Second), "confirm", nil)
	f.add(until.Add(3*time.Second), "last", nil)
	workers := []*store.Postgres{p, p2}
	errs := make([]error, 2)
	var wg sync.WaitGroup
	for i := range workers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = (reconcile.Worker{Reader: f, Repository: workers[i], Stream: s}).RunOnce(context.Background(), until.Add(4*time.Second))
		}(i)
	}
	wg.Wait()
	for _, e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	status, state, cost := statusOf(t, p, id)
	if status != "CONSUMED" || state != "FINAL" || cost != "2000" {
		t.Fatalf("two workers %s/%s/%s", status, state, cost)
	}
	var count int
	if err := p.Pool().QueryRow(context.Background(), `SELECT count(*) FROM actual_spend_ledger WHERE sponsorship_id=$1`, id).Scan(&count); err != nil || count != 1 {
		t.Fatalf("duplicate ledger %d %v", count, err)
	}
}

func TestReconciliationExpiryVsInclusion(t *testing.T) {
	p, f, s, id, hash, _, until := signedReservation(t)
	f.add(until.Add(-time.Second), "included", []types.Log{eventFor(s, hash, true, "3000")})
	f.add(until.Add(time.Second), "coverage", nil)
	f.add(until.Add(2*time.Second), "confirm", nil)
	f.add(until.Add(3*time.Second), "head", nil)
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = (reconcile.Worker{Reader: f, Repository: p, Stream: s}).RunOnce(context.Background(), until.Add(4*time.Second))
		}(i)
	}
	wg.Wait()
	for _, e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	status, state, cost := statusOf(t, p, id)
	if status != "CONSUMED" || state != "FINAL" || cost != "3000" {
		t.Fatalf("consume-expire race %s/%s/%s", status, state, cost)
	}
}

func TestReconciliationTerminalReorgRequiresManual(t *testing.T) {
	p, f, s, id, hash, _, _ := signedReservation(t)
	f.add(now.Add(time.Second), "included", []types.Log{eventFor(s, hash, true, "1000")})
	f.add(now.Add(2*time.Second), "confirm-2", nil)
	f.add(now.Add(3*time.Second), "confirm-3", nil)
	runWatcher(t, p, f, s, now.Add(4*time.Second))
	f.fork(1)
	f.add(now.Add(time.Second), "replacement-1", nil)
	f.add(now.Add(2*time.Second), "replacement-2", nil)
	f.add(now.Add(3*time.Second), "replacement-3", nil)
	err := (reconcile.Worker{Reader: f, Repository: p, Stream: s}).RunOnce(context.Background(), now.Add(5*time.Second))
	if !errors.Is(err, reconcile.ErrManualIntervention) {
		t.Fatalf("terminal reorg: %v", err)
	}
	status, _, _ := statusOf(t, p, id)
	if status != "CONSUMED" {
		t.Fatal("terminal accounting rewritten")
	}
	if err := p.Readiness(context.Background(), s); err == nil {
		t.Fatal("terminal contradiction readiness healthy")
	}
}

func TestReconciliationExpiredWatermarkReorgRequiresManual(t *testing.T) {
	p, f, s, id, _, _, until := signedReservation(t)
	f.add(until.Add(-time.Second), "before", nil)
	f.add(until, "at", nil)
	f.add(until.Add(time.Second), "past", nil)
	f.add(until.Add(2*time.Second), "confirm", nil)
	f.add(until.Add(3*time.Second), "final", nil)
	runWatcher(t, p, f, s, until.Add(4*time.Second))
	status, _, _ := statusOf(t, p, id)
	if status != "EXPIRED" {
		t.Fatal("unused expiry did not settle")
	}
	f.fork(2)
	for i := 2; i <= 5; i++ {
		f.add(until.Add(time.Duration(i)*time.Second), "replacement", nil)
	}
	err := (reconcile.Worker{Reader: f, Repository: p, Stream: s}).RunOnce(context.Background(), until.Add(6*time.Second))
	if !errors.Is(err, reconcile.ErrManualIntervention) {
		t.Fatalf("terminal expiry reorg: %v", err)
	}
	status, _, _ = statusOf(t, p, id)
	if status != "EXPIRED" {
		t.Fatal("terminal expiry rewritten")
	}
}

func TestReconciliationReaderAndStreamIdentity(t *testing.T) {
	p, f, s, _, _, _, _ := signedReservation(t)
	f.add(now.Add(time.Second), "empty", nil)
	runWatcher(t, p, f, s, now.Add(2*time.Second))
	wrong := s
	wrong.Paymaster[0] ^= 1
	if _, err := p.Checkpoint(context.Background(), wrong); err == nil {
		t.Fatal("changed paymaster reused stream")
	}
	wrong = s
	wrong.Confirmations++
	if _, err := p.Checkpoint(context.Background(), wrong); err == nil {
		t.Fatal("changed finality reused stream")
	}
	wrong = s
	wrong.ExpectedCodeHash = common.HexToHash("0x01")
	if err := (reconcile.Worker{Reader: f, Repository: p, Stream: wrong}).VerifyReader(context.Background()); err == nil {
		t.Fatal("wrong EntryPoint code accepted")
	}
	wrong = s
	other, _ := policy.ParseUint256("1")
	wrong.ChainID = policy.ChainID{Uint256: other}
	if err := (reconcile.Worker{Reader: f, Repository: p, Stream: wrong}).VerifyReader(context.Background()); err == nil {
		t.Fatal("wrong chain accepted")
	}
}

func TestDeepReorgOperatorRecovery(t *testing.T) {
	p, f, s, _, _, _, _ := signedReservation(t)
	f.add(now.Add(time.Second), "original-1", nil)
	for i := 2; i <= 10; i++ {
		f.add(now.Add(time.Duration(i)*time.Second), "original", nil)
	}
	runWatcher(t, p, f, s, now.Add(11*time.Second))
	f.fork(1)
	for i := 1; i <= 10; i++ {
		f.add(now.Add(time.Duration(i)*time.Second), "replacement", nil)
	}
	if err := (reconcile.Worker{Reader: f, Repository: p, Stream: s}).RunOnce(context.Background(), now.Add(12*time.Second)); !errors.Is(err, reconcile.ErrManualIntervention) {
		t.Fatalf("deep stop: %v", err)
	}
	plan, err := p.PlanRecovery(context.Background(), s, 0, f.blocks[0].Hash())
	if err != nil || !plan.Safe || plan.AffectedBlocks != 10 || plan.TerminalConflicts != 0 {
		t.Fatalf("dry run: %+v %v", plan, err)
	}
	wrong, err := p.PlanRecovery(context.Background(), s, 0, common.HexToHash("0x1234"))
	if err != nil || wrong.Safe {
		t.Fatalf("wrong recovery anchor accepted: %+v %v", wrong, err)
	}
	cp, err := p.Checkpoint(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	recovery := s
	recovery.Recovering = true
	if err := p.RollbackTo(context.Background(), recovery, cp, 0, f.blocks[0].Hash(), now.Add(13*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := p.Readiness(context.Background(), s); err == nil {
		t.Fatal("readiness restored before replay")
	}
	if err := (reconcile.Worker{Reader: f, Repository: p, Stream: recovery}).RunOnce(context.Background(), now.Add(14*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := p.Readiness(context.Background(), s); err == nil {
		t.Fatal("readiness restored before completion")
	}
	head := f.blocks[len(f.blocks)-1]
	if err := p.CompleteRecovery(context.Background(), s, head.Number.Uint64(), head.Hash(), now.Add(15*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := p.Readiness(context.Background(), s); err != nil {
		t.Fatalf("recovery readiness: %v", err)
	}
}

func TestIssuedBindingCannotBeRewrittenOrConsumedWithoutEvidence(t *testing.T) {
	p, _, _, id, _, _, _ := signedReservation(t)
	value, _ := policy.ParseUint256("1")
	if _, err := p.TransitionReservation(context.Background(), hex.EncodeToString(id), store.Consumed, &value, now.Add(2*time.Second)); !errors.Is(err, store.ErrStateConflict) {
		t.Fatalf("unproven signed consumption: %v", err)
	}
	if _, err := p.Pool().Exec(context.Background(), `UPDATE sponsorship_reservations SET user_op_hash=decode(repeat('11',32),'hex') WHERE sponsorship_id=$1`, id); err == nil {
		t.Fatal("issued hash binding was mutable")
	}
	status, _, _ := statusOf(t, p, id)
	if status != "RESERVED" {
		t.Fatal("unproven consumption changed status")
	}
}
