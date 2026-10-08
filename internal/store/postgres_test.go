package store_test

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/demo-lenoir/gasless-policy-engine/internal/admission"
	"github.com/demo-lenoir/gasless-policy-engine/internal/policy"
	"github.com/demo-lenoir/gasless-policy-engine/internal/store"
	"github.com/demo-lenoir/gasless-policy-engine/internal/telemetry"
	"github.com/prometheus/client_golang/prometheus"
)

const chain = "31337"

var now = time.Date(2030, 1, 2, 12, 0, 0, 0, time.UTC)

func fixture(t *testing.T, global, perChain, senderWei string, count int64) (*store.Postgres, *admission.Service, policy.RequestInput, string) {
	t.Helper()
	dsn := os.Getenv("PG_TEST_DSN")
	if dsn == "" {
		t.Skip("PG_TEST_DSN is required for PostgreSQL integration")
	}
	p, err := store.Open(context.Background(), dsn, 32, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.Pool().Exec(context.Background(), `TRUNCATE reconciliation_anomalies,actual_spend_ledger,userop_observations,reconciliation_blocks,reconciliation_checkpoints,audit_events,sponsorship_reservations,sponsorship_requests,budget_periods,policy_versions,service_controls CASCADE`)
	if err != nil {
		p.Close()
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	policyJSON, err := os.ReadFile("../../config/policy.example.json")
	if err != nil {
		t.Fatal(err)
	}
	cfg := admission.Config{NativeAsset: "ETH", GlobalDailyBudgetWei: global, Chains: []admission.ChainLimit{{ChainID: chain, NativeAsset: "ETH", DailyBudgetWei: perChain, SenderDailyWei: senderWei, SenderDailyCount: count}}, IssuanceProfiles: []admission.IssuerProfileConfig{testIssuerProfileConfig()}}
	svc, err := admission.NewService(policyJSON, cfg, p)
	if err != nil {
		t.Fatal(err)
	}
	input := testInput()
	r, err := policy.Normalize(input)
	if err != nil {
		t.Fatal(err)
	}
	amount, ok := policy.EstimatedUpperBound(r)
	if !ok {
		t.Fatal("upper bound overflow")
	}
	return p, svc, input, amount.String()
}
func testIssuerProfileConfig() admission.IssuerProfileConfig {
	return admission.IssuerProfileConfig{
		ChainID: chain, Paymaster: "0x3333333333333333333333333333333333333333",
		EntryPoint:      testInput().EntryPoint,
		AccountCodeHash: "0x0000000000000000000000000000000000000000000000000000000000000003",
		ExpectedSigner:  "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf",
	}
}
func testInput() policy.RequestInput {
	inner := []byte{0x12, 0x34, 0x56, 0x78, 0xaa}
	b := make([]byte, 4+96+32+32)
	copy(b[:4], []byte{0xb6, 0x1d, 0x27, 0xf6})
	for i := 16; i < 36; i++ {
		b[i] = 0x11
	}
	b[4+95] = 96
	binary.BigEndian.PutUint64(b[4+96+24:4+96+32], uint64(len(inner)))
	copy(b[4+96+32:], inner)
	return policy.RequestInput{ChainID: chain, EntryPoint: "0x433709009B8330FDa32311DF1C2AFA402eD8D009", Sender: "0x2222222222222222222222222222222222222222", Nonce: "7", CallData: "0x" + hex.EncodeToString(b), CallGasLimit: "100000", VerificationGasLimit: "100000", PreVerificationGas: "30000", PaymasterVerificationGasLimit: "80000", PaymasterPostOpGasLimit: "0", MaxFeePerGas: "10000000000", MaxPriorityFeePerGas: "1000000000"}
}
func multiplied(raw string, n int) string {
	v, _ := policy.ParseUint256(raw)
	m, _ := policy.ParseUint256(strconv.Itoa(n))
	out, ok := v.Mul(m)
	if !ok {
		panic("test amount overflow")
	}
	return out.String()
}
func limits(t *testing.T, multGlobal, multChain int, count int64) (*store.Postgres, *admission.Service, policy.RequestInput, string) {
	input := testInput()
	r, err := policy.Normalize(input)
	if err != nil {
		t.Fatal(err)
	}
	amount, _ := policy.EstimatedUpperBound(r)
	return fixture(t, multiplied(amount.String(), multGlobal), multiplied(amount.String(), multChain), multiplied(amount.String(), 200), count)
}
func submit(t *testing.T, s *admission.Service, key string, input policy.RequestInput, at time.Time) admission.Result {
	t.Helper()
	r, err := s.Admit(context.Background(), "client-a", key, input, at)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func key(i int) string { return fmt.Sprintf("request-key-%08d", i) }
func counts(t *testing.T, p *store.Postgres) (requests, reservations int) {
	t.Helper()
	if err := p.Pool().QueryRow(context.Background(), `SELECT count(*) FROM sponsorship_requests`).Scan(&requests); err != nil {
		t.Fatal(err)
	}
	if err := p.Pool().QueryRow(context.Background(), `SELECT count(*) FROM sponsorship_reservations`).Scan(&reservations); err != nil {
		t.Fatal(err)
	}
	return
}
func assertPeriod(t *testing.T, p *store.Postgres, scope string, held, admitted int64) {
	t.Helper()
	var h, a int64
	err := p.Pool().QueryRow(context.Background(), `SELECT held_count,admitted_count FROM budget_periods WHERE scope=$1 AND period_start=$2 AND chain_id=$3::numeric`, scope, now.Format("2006-01-02"), map[string]string{"ALL_CHAINS": "0", "GLOBAL": chain, "SENDER": chain}[scope]).Scan(&h, &a)
	if err != nil {
		t.Fatal(err)
	}
	if h != held || a != admitted {
		t.Fatalf("%s held=%d admitted=%d, want %d/%d", scope, h, a, held, admitted)
	}
}
func assertNoOversubscription(t *testing.T, p *store.Postgres) {
	t.Helper()
	rows, err := p.Pool().Query(context.Background(), `SELECT scope,limit_wei::text,held_wei::text,consumed_wei::text,held_count,consumed_count,admitted_count FROM budget_periods`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var scope, limitRaw, heldRaw, consumedRaw string
		var heldCount, consumedCount, admitted int64
		if err := rows.Scan(&scope, &limitRaw, &heldRaw, &consumedRaw, &heldCount, &consumedCount, &admitted); err != nil {
			t.Fatal(err)
		}
		limit, _ := new(big.Int).SetString(limitRaw, 10)
		held, _ := new(big.Int).SetString(heldRaw, 10)
		consumed, _ := new(big.Int).SetString(consumedRaw, 10)
		if held.Sign() < 0 || consumed.Sign() < 0 || new(big.Int).Add(held, consumed).Cmp(limit) > 0 {
			t.Fatalf("oversubscribed %s: %s + %s > %s", scope, heldRaw, consumedRaw, limitRaw)
		}
		if scope == "SENDER" && admitted < heldCount+consumedCount {
			t.Fatalf("sender count inconsistent")
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}
func raceRequests(t *testing.T, s *admission.Service, n int, transform func(int) *policy.RequestInput) (map[admission.Reason]int, []admission.Result) {
	t.Helper()
	start := make(chan struct{})
	results := make([]admission.Result, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			input := transform(i)
			results[i], errs[i] = s.Admit(context.Background(), "client-a", key(i), *input, now)
		}(i)
	}
	close(start)
	wg.Wait()
	got := map[admission.Reason]int{}
	for i, r := range results {
		if errs[i] != nil {
			t.Fatalf("request %d: %v", i, errs[i])
		}
		got[r.Reason]++
	}
	return got, results
}
func TestBudgetAndQuotaRaces(t *testing.T) {
	for repeat := 0; repeat < 3; repeat++ {
		t.Run(fmt.Sprintf("budget-%d", repeat), func(t *testing.T) {
			p, s, input, _ := limits(t, 10, 100, 1000)
			got, results := raceRequests(t, s, 100, func(i int) *policy.RequestInput { in := input; in.Nonce = strconv.Itoa(i + 1); return &in })
			if got[admission.Approved] != 10 || got[admission.GlobalBudgetExhausted] != 90 {
				t.Fatal(got)
			}
			_, res := counts(t, p)
			if res != 10 {
				t.Fatalf("reservations=%d", res)
			}
			assertPeriod(t, p, "ALL_CHAINS", 10, 0)
			assertPeriod(t, p, "SENDER", 10, 10)
			assertNoOversubscription(t, p)
			seen := map[string]bool{}
			for _, r := range results {
				if r.Approved {
					if seen[r.SponsorshipID] {
						t.Fatal("duplicate sponsorship ID")
					}
					seen[r.SponsorshipID] = true
				}
			}
		})
		t.Run(fmt.Sprintf("quota-%d", repeat), func(t *testing.T) {
			p, s, input, _ := limits(t, 200, 200, 20)
			got, _ := raceRequests(t, s, 100, func(i int) *policy.RequestInput { in := input; in.Nonce = strconv.Itoa(i + 1); return &in })
			if got[admission.Approved] != 20 || got[admission.QuotaExhausted] != 80 {
				t.Fatal(got)
			}
			_, res := counts(t, p)
			if res != 20 {
				t.Fatalf("reservations=%d", res)
			}
			assertPeriod(t, p, "SENDER", 20, 20)
			assertNoOversubscription(t, p)
		})
	}
}
func TestChainBudgetAndIndependentSenders(t *testing.T) {
	p, s, input, _ := limits(t, 100, 3, 20)
	got, _ := raceRequests(t, s, 30, func(i int) *policy.RequestInput {
		in := input
		in.Nonce = strconv.Itoa(i + 1)
		if i%2 == 1 {
			in.Sender = "0x3333333333333333333333333333333333333334"
		}
		return &in
	})
	if got[admission.Approved] != 3 || got[admission.ChainBudgetExhausted] != 27 {
		t.Fatal(got)
	}
	assertPeriod(t, p, "GLOBAL", 3, 0)
}

func TestIndependentSenderQuota(t *testing.T) {
	p, s, input, _ := limits(t, 100, 100, 1)
	got, _ := raceRequests(t, s, 100, func(i int) *policy.RequestInput {
		in := input
		in.Nonce = strconv.Itoa(i + 1)
		if i%2 == 1 {
			in.Sender = "0x3333333333333333333333333333333333333334"
		}
		return &in
	})
	if got[admission.Approved] != 2 || got[admission.QuotaExhausted] != 98 {
		t.Fatal(got)
	}
	_, res := counts(t, p)
	if res != 2 {
		t.Fatal(res)
	}
}
func TestIdempotencyRacesAndRestart(t *testing.T) {
	p, s, input, _ := limits(t, 2, 2, 2)
	const n = 100
	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make([]admission.Result, n)
	errs := make([]error, n)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results[i], errs[i] = s.Admit(context.Background(), "client-a", key(1), input, now)
		}(i)
	}
	close(start)
	wg.Wait()
	for i, r := range results {
		if errs[i] != nil || !r.Approved || r.RequestID != results[0].RequestID || r.SponsorshipID != results[0].SponsorshipID {
			t.Fatalf("duplicate %d: %+v %v", i, r, errs[i])
		}
	}
	req, res := counts(t, p)
	if req != 1 || res != 1 {
		t.Fatalf("rows %d/%d", req, res)
	}
	assertPeriod(t, p, "SENDER", 1, 1)
	p2, err := store.Open(context.Background(), os.Getenv("PG_TEST_DSN"), 4, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer p2.Close()
	policyJSON, _ := os.ReadFile("../../config/policy.example.json")
	cfg := admission.Config{NativeAsset: "ETH", GlobalDailyBudgetWei: multiplied(results[0].EstimatedUpperBoundWei, 2), Chains: []admission.ChainLimit{{ChainID: chain, NativeAsset: "ETH", DailyBudgetWei: multiplied(results[0].EstimatedUpperBoundWei, 2), SenderDailyWei: multiplied(results[0].EstimatedUpperBoundWei, 200), SenderDailyCount: 2}}}
	restarted, err := admission.NewService(policyJSON, cfg, p2)
	if err != nil {
		t.Fatal(err)
	}
	retry := submit(t, restarted, key(1), input, now.Add(time.Hour))
	if !retry.Replayed || retry.SponsorshipID != results[0].SponsorshipID {
		t.Fatalf("restart retry: %+v", retry)
	}
	versionTwo := []byte(strings.Replace(string(policyJSON), `"version": 1`, `"version": 2`, 1))
	if string(versionTwo) == string(policyJSON) {
		t.Fatal("policy version fixture unchanged")
	}
	changed, err := admission.NewService(versionTwo, cfg, p2)
	if err != nil {
		t.Fatal(err)
	}
	older := submit(t, changed, key(1), input, now.Add(time.Hour))
	if !older.Replayed || older.PolicyVersion != 1 || older.SponsorshipID != retry.SponsorshipID {
		t.Fatalf("policy change retry: %+v", older)
	}
	misconfigured := cfg
	misconfigured.GlobalDailyBudgetWei = multiplied(results[0].EstimatedUpperBoundWei, 3)
	badService, err := admission.NewService(policyJSON, misconfigured, p2)
	if err != nil {
		t.Fatal(err)
	}
	other := input
	other.Nonce = "9"
	badResult, badErr := badService.Admit(context.Background(), "client-a", key(3), other, now)
	if !errors.Is(badErr, admission.ErrPolicyVersionConflict) || badResult.Reason != admission.PolicyVersionConflict {
		t.Fatalf("version conflict result=%+v err=%v", badResult, badErr)
	}
	input.Nonce = "8"
	conflict := submit(t, restarted, key(1), input, now)
	if conflict.Reason != admission.IdempotencyConflict {
		t.Fatal(conflict)
	}
	req, res = counts(t, p)
	if req != 1 || res != 1 {
		t.Fatalf("rows after conflict %d/%d", req, res)
	}
}
func TestConflictingIdempotencyRace(t *testing.T) {
	p, s, input, _ := limits(t, 2, 2, 2)
	a := input
	b := input
	b.Nonce = "8"
	start := make(chan struct{})
	var wg sync.WaitGroup
	results := make([]admission.Result, 100)
	errs := make([]error, 100)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			in := a
			if i%2 == 1 {
				in = b
			}
			results[i], errs[i] = s.Admit(context.Background(), "client-a", key(99), in, now)
		}(i)
	}
	close(start)
	wg.Wait()
	approved, conflicts := 0, 0
	for i, r := range results {
		if errs[i] != nil {
			t.Fatal(errs[i])
		}
		if r.Approved {
			approved++
		} else if r.Reason == admission.IdempotencyConflict {
			conflicts++
		} else {
			t.Fatalf("caller %d: %+v", i, r)
		}
	}
	if approved != 50 || conflicts != 50 {
		t.Fatalf("approved=%d conflicts=%d", approved, conflicts)
	}
	req, res := counts(t, p)
	if req != 1 || res != 1 {
		t.Fatalf("rows %d/%d", req, res)
	}
}
func TestLifecycleAndAudit(t *testing.T) {
	p, s, input, _ := limits(t, 2, 2, 2)
	r := submit(t, s, key(1), input, now)
	if !r.Approved {
		t.Fatal(r)
	}
	released, err := p.TransitionReservation(context.Background(), r.SponsorshipID, store.Released, nil, now.Add(time.Second))
	if err != nil || !released.Changed {
		t.Fatal(released, err)
	}
	again, err := p.TransitionReservation(context.Background(), r.SponsorshipID, store.Released, nil, now.Add(2*time.Second))
	if err != nil || again.Changed {
		t.Fatal(again, err)
	}
	_, err = p.TransitionReservation(context.Background(), r.SponsorshipID, store.Consumed, nil, now)
	if !errors.Is(err, store.ErrStateConflict) {
		t.Fatal(err)
	}
	assertPeriod(t, p, "SENDER", 0, 1)
	next := input
	next.Nonce = "8"
	r2 := submit(t, s, key(2), next, now)
	if !r2.Approved {
		t.Fatal(r2)
	}
	expired, err := p.ExpireReservations(context.Background(), r2.ValidUntil.Add(time.Second), 10)
	if err != nil || expired != 1 {
		t.Fatal(expired, err)
	}
	expired, err = p.ExpireReservations(context.Background(), r2.ValidUntil.Add(time.Second), 10)
	if err != nil || expired != 0 {
		t.Fatal(expired, err)
	}
	assertPeriod(t, p, "SENDER", 0, 2)
	third := input
	third.Nonce = "9"
	denied := submit(t, s, key(3), third, now)
	if denied.Reason != admission.QuotaExhausted {
		t.Fatal(denied)
	}
	var events int
	err = p.Pool().QueryRow(context.Background(), `SELECT count(*) FROM audit_events`).Scan(&events)
	if err != nil || events != 8 {
		t.Fatalf("audit events=%d err=%v", events, err)
	}
}
func TestConsumeAndIllegalTransitions(t *testing.T) {
	p, s, input, _ := limits(t, 2, 2, 2)
	r := submit(t, s, key(1), input, now)
	actual, _ := policy.ParseUint256("1000")
	state, err := p.TransitionReservation(context.Background(), r.SponsorshipID, store.Consumed, &actual, now.Add(time.Second))
	if err != nil || !state.Changed {
		t.Fatal(state, err)
	}
	state, err = p.TransitionReservation(context.Background(), r.SponsorshipID, store.Consumed, &actual, now.Add(time.Second))
	if err != nil || state.Changed {
		t.Fatal(state, err)
	}
	_, err = p.TransitionReservation(context.Background(), r.SponsorshipID, store.Released, nil, now)
	if !errors.Is(err, store.ErrStateConflict) {
		t.Fatal(err)
	}
	assertPeriod(t, p, "SENDER", 0, 1)
}
func TestUTCPeriodBoundary(t *testing.T) {
	p, s, input, _ := limits(t, 1, 1, 1)
	before := time.Date(2030, 1, 2, 23, 59, 59, 0, time.UTC)
	r := submit(t, s, key(1), input, before)
	if !r.Approved {
		t.Fatal(r)
	}
	next := input
	next.Nonce = "8"
	after := before.Add(time.Second)
	r2 := submit(t, s, key(2), next, after)
	if !r2.Approved {
		t.Fatal(r2)
	}
	var periods int
	if err := p.Pool().QueryRow(context.Background(), `SELECT count(*) FROM budget_periods WHERE scope='ALL_CHAINS'`).Scan(&periods); err != nil || periods != 2 {
		t.Fatal(periods, err)
	}
}

func TestMidnightRaceAndLastBudgetSlot(t *testing.T) {
	p, s, input, _ := limits(t, 1, 1, 100)
	boundary := time.Date(2030, 1, 3, 0, 0, 0, 0, time.UTC)
	start := make(chan struct{})
	var wg sync.WaitGroup
	results := make([]admission.Result, 4)
	errs := make([]error, 4)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			in := input
			in.Nonce = strconv.Itoa(i + 1)
			at := boundary
			if i < 2 {
				at = boundary.Add(-time.Nanosecond)
			}
			results[i], errs[i] = s.Admit(context.Background(), "client-a", key(i), in, at)
		}(i)
	}
	close(start)
	wg.Wait()
	success, denied := 0, 0
	for i, r := range results {
		if errs[i] != nil {
			t.Fatal(errs[i])
		}
		if r.Approved {
			success++
		} else if r.Reason == admission.GlobalBudgetExhausted {
			denied++
		} else {
			t.Fatalf("%d: %+v", i, r)
		}
	}
	if success != 2 || denied != 2 {
		t.Fatalf("success=%d denied=%d", success, denied)
	}
	_, res := counts(t, p)
	if res != 2 {
		t.Fatal(res)
	}
}

func TestTerminalTransitionRaces(t *testing.T) {
	for _, pair := range [][2]store.Transition{{store.Released, store.Expired}, {store.Consumed, store.Expired}} {
		t.Run(string(pair[0])+"-"+string(pair[1]), func(t *testing.T) {
			p, s, input, _ := limits(t, 1, 1, 1)
			r := submit(t, s, key(1), input, now)
			if !r.Approved {
				t.Fatal(r)
			}
			start := make(chan struct{})
			var wg sync.WaitGroup
			states := make([]store.ReservationState, 2)
			errs := make([]error, 2)
			for i, to := range pair {
				wg.Add(1)
				go func(i int, to store.Transition) {
					defer wg.Done()
					<-start
					var actual *policy.Uint256
					if to == store.Consumed {
						v, _ := policy.ParseUint256("1000")
						actual = &v
					}
					states[i], errs[i] = p.TransitionReservation(context.Background(), r.SponsorshipID, to, actual, r.ValidUntil.Add(time.Second))
				}(i, to)
			}
			close(start)
			wg.Wait()
			changed, conflict := 0, 0
			for i := range states {
				if states[i].Changed {
					changed++
				} else if errors.Is(errs[i], store.ErrStateConflict) {
					conflict++
				} else {
					t.Fatalf("state=%+v err=%v", states[i], errs[i])
				}
			}
			if changed != 1 || conflict != 1 {
				t.Fatalf("changed=%d conflict=%d", changed, conflict)
			}
			assertPeriod(t, p, "ALL_CHAINS", 0, 0)
			var terminalEvents int
			if err := p.Pool().QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE event_type IN ('RELEASED','EXPIRED','CONSUMED')`).Scan(&terminalEvents); err != nil || terminalEvents != 1 {
				t.Fatal(terminalEvents, err)
			}
		})
	}
}

func TestTwoExpiryWorkers(t *testing.T) {
	p, s, input, _ := limits(t, 20, 20, 20)
	for i := 0; i < 20; i++ {
		in := input
		in.Nonce = strconv.Itoa(i + 1)
		r := submit(t, s, key(i), in, now)
		if !r.Approved {
			t.Fatal(r)
		}
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	results := make([]int, 2)
	errs := make([]error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results[i], errs[i] = p.ExpireReservations(context.Background(), now.Add(2*time.Minute), 20)
		}(i)
	}
	close(start)
	wg.Wait()
	if errs[0] != nil || errs[1] != nil || results[0]+results[1] != 20 {
		t.Fatalf("expired=%v err=%v", results, errs)
	}
	assertPeriod(t, p, "ALL_CHAINS", 0, 0)
	assertPeriod(t, p, "SENDER", 0, 20)
}
func TestDatabaseCancellationLeavesNoPartialAdmission(t *testing.T) {
	p, s, input, _ := limits(t, 2, 2, 2)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := s.Admit(ctx, "client-a", key(1), input, now)
	if err == nil {
		t.Fatal("cancelled admission succeeded")
	}
	req, res := counts(t, p)
	if req != 0 || res != 0 {
		t.Fatalf("partial rows %d/%d", req, res)
	}
	lock, err := p.Pool().Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Rollback(context.Background())
	_, err = lock.Exec(context.Background(), `INSERT INTO budget_periods(chain_id,period_start,scope,subject,limit_wei) VALUES(0,$1,'ALL_CHAINS',decode(repeat('00',20),'hex'),100000000000000000)`, now.Format("2006-01-02"))
	if err != nil {
		t.Fatal(err)
	}
	short, c := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer c()
	_, err = s.Admit(short, "client-a", key(2), input, now)
	if err == nil {
		t.Fatal("locked admission did not time out")
	}
	lock.Rollback(context.Background())
	req, res = counts(t, p)
	if req != 0 || res != 0 {
		t.Fatalf("partial rows after timeout %d/%d", req, res)
	}
}

func TestEmergencyDisableDeniesBeforeReservation(t *testing.T) {
	p, s, input, _ := limits(t, 10, 10, 10)
	_, err := p.Pool().Exec(context.Background(), `INSERT INTO service_controls(chain_id,issuance_disabled) VALUES(31337,true)`)
	if err != nil {
		t.Fatal(err)
	}
	r := submit(t, s, key(1), input, now)
	if r.Reason != admission.EmergencyDisabled || r.Approved {
		t.Fatal(r)
	}
	requests, reservations := counts(t, p)
	if requests != 1 || reservations != 0 {
		t.Fatalf("rows %d/%d", requests, reservations)
	}
}
func TestUnavailableDatabase(t *testing.T) {
	p, s, input, _ := limits(t, 2, 2, 2)
	p.Close()
	r, err := s.Admit(context.Background(), "client-a", key(1), input, now)
	if err == nil || r.Reason != admission.StorageUnavailable {
		t.Fatalf("result=%+v err=%v", r, err)
	}
}

func TestStaticDenialIsAuditedWithoutReservation(t *testing.T) {
	p, s, input, _ := limits(t, 2, 2, 2)
	input.ChainID = "1"
	r := submit(t, s, key(1), input, now)
	if r.Approved || r.Reason != admission.StaticPolicyDenied || r.PolicyReason != policy.ReasonChainNotAllowed {
		t.Fatal(r)
	}
	req, res := counts(t, p)
	if req != 1 || res != 0 {
		t.Fatalf("rows %d/%d", req, res)
	}
	var events int
	if err := p.Pool().QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE request_id=$1`, r.RequestID).Scan(&events); err != nil || events != 2 {
		t.Fatal(events, err)
	}
	malformed := input
	malformed.CallData = "0x01"
	r2 := submit(t, s, key(2), malformed, now)
	if r2.PolicyReason != policy.ReasonUnsupportedCallShape {
		t.Fatal(r2)
	}
	req, res = counts(t, p)
	if req != 1 || res != 0 {
		t.Fatalf("malformed request persisted %d/%d", req, res)
	}
}

func TestPublishedLimitReductionBlocksNewHolds(t *testing.T) {
	p, s, input, amount := limits(t, 3, 3, 3)
	first := submit(t, s, key(1), input, now)
	if !first.Approved {
		t.Fatal(first)
	}
	policyJSON, err := os.ReadFile("../../config/policy.example.json")
	if err != nil {
		t.Fatal(err)
	}
	versionTwo := []byte(strings.Replace(string(policyJSON), `"version": 1`, `"version": 2`, 1))
	cfg := admission.Config{NativeAsset: "ETH", GlobalDailyBudgetWei: amount, Chains: []admission.ChainLimit{{ChainID: chain, NativeAsset: "ETH", DailyBudgetWei: amount, SenderDailyWei: amount, SenderDailyCount: 1}}}
	newer, err := admission.NewService(versionTwo, cfg, p)
	if err != nil {
		t.Fatal(err)
	}
	next := input
	next.Nonce = "8"
	denied := submit(t, newer, key(2), next, now)
	if denied.Reason != admission.GlobalBudgetExhausted {
		t.Fatal(denied)
	}
	_, reservations := counts(t, p)
	if reservations != 1 {
		t.Fatal(reservations)
	}
	assertNoOversubscription(t, p)
}

func TestBoundedSerializationRetry(t *testing.T) {
	p, s, input, _ := limits(t, 2, 2, 2)
	commands := []string{
		`CREATE SEQUENCE phase2_retry_seq`,
		`CREATE FUNCTION phase2_retry_once() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF nextval('phase2_retry_seq')=1 THEN RAISE EXCEPTION 'retry' USING ERRCODE='40001'; END IF; RETURN NEW; END $$`,
		`CREATE TRIGGER phase2_retry_trigger BEFORE INSERT ON sponsorship_requests FOR EACH ROW EXECUTE FUNCTION phase2_retry_once()`,
	}
	for _, sql := range commands {
		if _, err := p.Pool().Exec(context.Background(), sql); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, sql := range []string{`DROP TRIGGER phase2_retry_trigger ON sponsorship_requests`, `DROP FUNCTION phase2_retry_once()`, `DROP SEQUENCE phase2_retry_seq`} {
			_, _ = p.Pool().Exec(context.Background(), sql)
		}
	})
	r := submit(t, s, key(1), input, now)
	if !r.Approved {
		t.Fatal(r)
	}
	var calls int
	if err := p.Pool().QueryRow(context.Background(), `SELECT last_value FROM phase2_retry_seq`).Scan(&calls); err != nil || calls != 2 {
		t.Fatalf("attempts=%d err=%v", calls, err)
	}
	req, res := counts(t, p)
	if req != 1 || res != 1 {
		t.Fatalf("rows %d/%d", req, res)
	}
}

func TestCommittedMetricsAndLedgerRefresh(t *testing.T) {
	p, s, input, _ := limits(t, 2, 2, 2)
	reg := prometheus.NewRegistry()
	m, err := telemetry.New(reg)
	if err != nil {
		t.Fatal(err)
	}
	s.SetObserver(m)
	p.SetObserver(m)
	r := submit(t, s, key(1), input, now)
	if !r.Approved {
		t.Fatal(r)
	}
	n, err := p.ExpireReservations(context.Background(), r.ValidUntil.Add(time.Second), 10)
	if err != nil || n != 1 {
		t.Fatal(n, err)
	}
	if err := m.RefreshFromLedger(context.Background(), p, now, multiplied(r.EstimatedUpperBoundWei, 2)); err != nil {
		t.Fatal(err)
	}
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]float64{}
	for _, family := range families {
		for _, metric := range family.Metric {
			if metric.Gauge != nil {
				found[family.GetName()] = metric.Gauge.GetValue()
			}
			if metric.Counter != nil {
				found[family.GetName()] += metric.Counter.GetValue()
			}
		}
	}
	if found["gasless_sponsorships_reserved"] != 0 || found["gasless_sponsorships_expired_total"] != 1 || found["gasless_requests_total"] != 1 {
		t.Fatal(found)
	}
}
