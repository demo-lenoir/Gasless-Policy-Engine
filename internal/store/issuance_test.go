package store_test

import (
	"context"
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/demo-lenoir/gasless-policy-engine/internal/admission"
	"github.com/demo-lenoir/gasless-policy-engine/internal/issuance"
	"github.com/demo-lenoir/gasless-policy-engine/internal/policy"
	"github.com/demo-lenoir/gasless-policy-engine/internal/signing"
	"github.com/demo-lenoir/gasless-policy-engine/internal/store"
	"github.com/ethereum/go-ethereum/crypto"
)

type controlledSigner struct {
	delegate        signing.SponsorSigner
	started         chan struct{}
	release         chan struct{}
	calls           atomic.Int32
	fault           string
	addressOverride *policy.Address
}

func (s *controlledSigner) Address(ctx context.Context) (policy.Address, error) {
	if s.fault == "address" {
		return policy.Address{}, errors.New("unavailable")
	}
	if s.addressOverride != nil {
		return *s.addressOverride, nil
	}
	return s.delegate.Address(ctx)
}
func (s *controlledSigner) SignDigest(ctx context.Context, d [32]byte) ([]byte, error) {
	s.calls.Add(1)
	if s.started != nil {
		select {
		case s.started <- struct{}{}:
		default:
		}
	}
	if s.release != nil {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.release:
		}
	}
	if s.fault == "signature" {
		return make([]byte, 65), nil
	}
	if s.fault == "unavailable" {
		return nil, errors.New("unavailable")
	}
	if s.fault == "ignore_timeout" {
		time.Sleep(30 * time.Millisecond)
	}
	sig, err := s.delegate.SignDigest(ctx, d)
	if err != nil {
		return nil, err
	}
	if s.fault == "wrong_v" {
		sig[64] = 0
	}
	if s.fault == "high_s" {
		n := crypto.S256().Params().N
		value := new(big.Int).SetBytes(sig[32:64])
		new(big.Int).Sub(n, value).FillBytes(sig[32:64])
	}
	return sig, nil
}

func signerFixture(t *testing.T) (*controlledSigner, policy.Address) {
	t.Helper()
	// Scalar one is a public deterministic fixture, never a runtime secret.
	var scalar [32]byte
	scalar[31] = 1
	key, err := crypto.ToECDSA(scalar[:])
	if err != nil {
		t.Fatal(err)
	}
	dev, err := signing.NewDevLocalSigner(key, true)
	if err != nil {
		t.Fatal(err)
	}
	addr, err := dev.Address(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return &controlledSigner{delegate: dev}, addr
}

func issuanceFixture(t *testing.T, p *store.Postgres, signer signing.SponsorSigner, addr policy.Address, clock func() time.Time) *issuance.Service {
	t.Helper()
	config := issuanceConfig(addr)
	svc, err := issuance.NewService(config, p, signer, clock)
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func issuanceConfig(addr policy.Address) issuance.Config {
	paymaster, _ := policy.ParseAddress("0x3333333333333333333333333333333333333333")
	entry, _ := policy.ParseAddress(testInput().EntryPoint)
	chainValue, _ := policy.ParseUint256(chain)
	var codeHash [32]byte
	codeHash[31] = 3
	return issuance.Config{PolicyVersion: 1, ChainID: policy.ChainID{Uint256: chainValue}, Paymaster: paymaster, EntryPoint: entry, AccountCodeHash: codeHash, ExpectedSigner: addr, ClaimLease: 20 * time.Second, SignerTimeout: 10 * time.Second}
}

func TestSigningConcurrentAndRestart(t *testing.T) {
	p, admitter, input, _ := limits(t, 3, 3, 3)
	admitted := submit(t, admitter, key(1), input, now)
	if !admitted.Approved {
		t.Fatal(admitted.Reason)
	}
	signer, addr := signerFixture(t)
	clock := func() time.Time { return now.Add(time.Second) }
	svc := issuanceFixture(t, p, signer, addr, clock)
	const n = 100
	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make([]issuance.Artifact, n)
	reasons := make([]issuance.Reason, n)
	errs := make([]error, n)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results[i], reasons[i], errs[i] = svc.Issue(context.Background(), admitted.SponsorshipID)
		}(i)
	}
	close(start)
	wg.Wait()
	for i := range results {
		if errs[i] != nil || results[i].Digest != results[0].Digest || results[i].PaymasterAndData != results[0].PaymasterAndData || results[i].SponsorshipID != results[0].SponsorshipID || !results[i].ValidUntil.Equal(admitted.ValidUntil) {
			t.Fatalf("caller %d: %s %v", i, reasons[i], errs[i])
		}
	}
	if signer.calls.Load() != 1 {
		t.Fatalf("signer calls=%d", signer.calls.Load())
	}
	var count int
	if err := p.Pool().QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE event_type='AUTHORIZATION_ISSUED'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("issued audits=%d %v", count, err)
	}
	p2, err := store.Open(context.Background(), testDSN(t), 4, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer p2.Close()
	restarted := issuanceFixture(t, p2, signer, addr, clock)
	got, reason, err := restarted.Issue(context.Background(), admitted.SponsorshipID)
	if err != nil || reason != issuance.AlreadyIssued || got.Digest != results[0].Digest || got.PaymasterAndData != results[0].PaymasterAndData || !got.ValidUntil.Equal(results[0].ValidUntil) || signer.calls.Load() != 1 {
		t.Fatalf("restart result %s %v", reason, err)
	}
	assertPeriod(t, p, "ALL_CHAINS", 1, 0)
}

func testDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("PG_TEST_DSN")
	if dsn == "" {
		t.Fatal("missing test DSN")
	}
	return dsn
}

func TestSigningClaimCrashBoundaries(t *testing.T) {
	p, admitter, input, _ := limits(t, 3, 3, 3)
	admitted := submit(t, admitter, key(2), input, now)
	raw, _ := hex.DecodeString(admitted.SponsorshipID)
	var id [32]byte
	copy(id[:], raw)
	signer, addr := signerFixture(t)
	profile := issuanceConfig(addr).Profile()
	first, err := p.ClaimSigning(context.Background(), id, profile, now.Add(time.Second), 10*time.Second)
	if err != nil || first.Reason != issuance.Issued {
		t.Fatalf("first claim %s %v", first.Reason, err)
	}
	second, err := p.ClaimSigning(context.Background(), id, profile, now.Add(2*time.Second), 10*time.Second)
	if err != nil || second.Reason != issuance.SigningInProgress {
		t.Fatalf("duplicate claim %s %v", second.Reason, err)
	}
	third, err := p.ClaimSigning(context.Background(), id, profile, now.Add(11*time.Second), 10*time.Second)
	if err != nil || third.Reason != issuance.Issued || third.Claim.Generation != first.Claim.Generation+1 || third.Claim.SponsorshipID != first.Claim.SponsorshipID || !third.Claim.ValidUntil.Equal(first.Claim.ValidUntil) {
		t.Fatalf("recovered claim %s %v", third.Reason, err)
	}
	stale, err := p.CheckSigningClaim(context.Background(), first.Claim, now.Add(12*time.Second))
	if err != nil || stale != issuance.SigningClaimLost {
		t.Fatalf("stale owner %s %v", stale, err)
	}
	svc := issuanceFixture(t, p, signer, addr, func() time.Time { return now.Add(22 * time.Second) })
	artifact, reason, err := svc.Issue(context.Background(), admitted.SponsorshipID)
	if err != nil || reason != issuance.Issued || artifact.SponsorshipID != id {
		t.Fatalf("recovery issuance %s %v", reason, err)
	}
	if signer.calls.Load() != 1 {
		t.Fatal("unexpected signer calls")
	}
}

func TestEmergencyDisableDuringSigning(t *testing.T) {
	p, admitter, input, _ := limits(t, 3, 3, 3)
	admitted := submit(t, admitter, key(3), input, now)
	signer, addr := signerFixture(t)
	signer.started = make(chan struct{}, 1)
	signer.release = make(chan struct{})
	svc := issuanceFixture(t, p, signer, addr, func() time.Time { return now.Add(time.Second) })
	result := make(chan issuance.Reason, 1)
	fail := make(chan error, 1)
	go func() { _, r, e := svc.Issue(context.Background(), admitted.SponsorshipID); result <- r; fail <- e }()
	<-signer.started
	_, err := p.Pool().Exec(context.Background(), `UPDATE service_controls SET issuance_disabled=TRUE,generation=generation+1 WHERE chain_id=$1::numeric`, chain)
	if err != nil {
		t.Fatal(err)
	}
	close(signer.release)
	if r, e := <-result, <-fail; r != issuance.EmergencyDisabled || e != nil {
		t.Fatalf("post-sign gate %s %v", r, e)
	}
	raw, _ := hex.DecodeString(admitted.SponsorshipID)
	var id [32]byte
	copy(id[:], raw)
	artifact, err := p.ReadAuthorization(context.Background(), id)
	if err != nil || artifact != nil {
		t.Fatalf("artifact exposed %v %v", artifact, err)
	}
	var count int
	err = p.Pool().QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE event_type='SIGNING_BLOCKED_EMERGENCY'`).Scan(&count)
	if err != nil || count != 1 {
		t.Fatalf("emergency audit %d %v", count, err)
	}
	assertPeriod(t, p, "ALL_CHAINS", 1, 0)
}

func TestSigningFailuresAndExpiryHold(t *testing.T) {
	for _, fault := range []string{"address", "signature", "unavailable"} {
		t.Run(fault, func(t *testing.T) {
			p, admitter, input, _ := limits(t, 3, 3, 3)
			admitted := submit(t, admitter, key(4), input, now)
			signer, addr := signerFixture(t)
			signer.fault = fault
			svc := issuanceFixture(t, p, signer, addr, func() time.Time { return now.Add(time.Second) })
			_, reason, err := svc.Issue(context.Background(), admitted.SponsorshipID)
			expected := issuance.SignerUnavailable
			if fault == "signature" {
				expected = issuance.InvalidSignature
			}
			if err != nil || reason != expected {
				t.Fatalf("fault %s reason %s error %v", fault, reason, err)
			}
			assertPeriod(t, p, "ALL_CHAINS", 1, 0)
		})
	}
	p, admitter, input, _ := limits(t, 3, 3, 3)
	admitted := submit(t, admitter, key(5), input, now)
	signer, addr := signerFixture(t)
	current := now.Add(time.Second)
	svc := issuanceFixture(t, p, signer, addr, func() time.Time { return current })
	artifact, reason, err := svc.Issue(context.Background(), admitted.SponsorshipID)
	if err != nil || reason != issuance.Issued {
		t.Fatalf("issue %s %v", reason, err)
	}
	for _, at := range []time.Time{admitted.ValidUntil.Add(-time.Nanosecond), admitted.ValidUntil, admitted.ValidUntil.Add(time.Second)} {
		count, err := p.ExpireReservations(context.Background(), at, 10)
		if err != nil || count != 0 {
			t.Fatalf("signed hold expired at %v: %d %v", at, count, err)
		}
	}
	for i, at := range []time.Time{admitted.ValidUntil.Add(-time.Nanosecond), admitted.ValidUntil, admitted.ValidUntil.Add(time.Second), admitted.ValidUntil.Add(2 * time.Second)} {
		count, err := p.MarkExpiredArtifacts(context.Background(), at, 10)
		want := 0
		if i == 2 {
			want = 1
		}
		if err != nil || count != want {
			t.Fatalf("mark elapsed artifact at %v: %d %v", at, count, err)
		}
	}
	assertPeriod(t, p, "ALL_CHAINS", 1, 0)
	current = admitted.ValidUntil.Add(time.Second)
	retry, retryReason, retryErr := svc.Issue(context.Background(), admitted.SponsorshipID)
	if retryErr != nil || retryReason != issuance.AlreadyIssued || retry.Digest != artifact.Digest || retry.PaymasterAndData != artifact.PaymasterAndData || !retry.ValidUntil.Equal(artifact.ValidUntil) {
		t.Fatalf("issued retry %s %v", retryReason, retryErr)
	}
	if signer.calls.Load() != 1 {
		t.Fatalf("resigned after expiry: %d", signer.calls.Load())
	}
}

func TestSigningExpiredAndRevoked(t *testing.T) {
	for _, mode := range []string{"expired", "revoked"} {
		t.Run(mode, func(t *testing.T) {
			p, admitter, input, _ := limits(t, 3, 3, 3)
			admitted := submit(t, admitter, key(6), input, now)
			signer, addr := signerFixture(t)
			clock := func() time.Time { return now.Add(time.Second) }
			if mode == "expired" {
				clock = func() time.Time { return admitted.ValidUntil }
			}
			if mode == "revoked" {
				_, err := p.Pool().Exec(context.Background(), `UPDATE policy_versions SET issuance_revoked=TRUE WHERE version=1`)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = p.Pool().Exec(context.Background(), `UPDATE policy_versions SET issuance_revoked=FALSE WHERE version=1`); err == nil {
					t.Fatal("revoked policy version was restored")
				}
			}
			svc := issuanceFixture(t, p, signer, addr, clock)
			_, reason, err := svc.Issue(context.Background(), admitted.SponsorshipID)
			expected := issuance.AuthorizationExpired
			if mode == "revoked" {
				expected = issuance.PolicyRevoked
			}
			if err != nil || reason != expected || signer.calls.Load() != 0 {
				t.Fatalf("%s: %s %v calls=%d", mode, reason, err, signer.calls.Load())
			}
		})
	}
}

func TestSigningAtLastInstantBeforeExpiry(t *testing.T) {
	p, admitter, input, _ := limits(t, 3, 3, 3)
	admitted := submit(t, admitter, key(17), input, now)
	signer, addr := signerFixture(t)
	svc := issuanceFixture(t, p, signer, addr, func() time.Time { return admitted.ValidUntil.Add(-time.Nanosecond) })
	artifact, reason, err := svc.Issue(context.Background(), admitted.SponsorshipID)
	if err != nil || reason != issuance.Issued || !artifact.ValidUntil.Equal(admitted.ValidUntil) {
		t.Fatalf("last instant issue %s %v", reason, err)
	}
	assertPeriod(t, p, "ALL_CHAINS", 1, 0)
}

func TestConcurrentSignedExpiryWorkers(t *testing.T) {
	p, admitter, input, _ := limits(t, 3, 3, 3)
	admitted := submit(t, admitter, key(18), input, now)
	signer, addr := signerFixture(t)
	svc := issuanceFixture(t, p, signer, addr, func() time.Time { return now.Add(time.Second) })
	if _, reason, err := svc.Issue(context.Background(), admitted.SponsorshipID); err != nil || reason != issuance.Issued {
		t.Fatalf("issue %s %v", reason, err)
	}
	var wg sync.WaitGroup
	counts := make([]int, 2)
	errs := make([]error, 2)
	for i := range counts {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			counts[i], errs[i] = p.MarkExpiredArtifacts(context.Background(), admitted.ValidUntil.Add(time.Second), 10)
		}(i)
	}
	wg.Wait()
	if errs[0] != nil || errs[1] != nil || counts[0]+counts[1] != 1 {
		t.Fatalf("expiry workers: %v %v %v", counts, errs[0], errs[1])
	}
	var events int
	if err := p.Pool().QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE event_type='AUTHORIZATION_EXPIRED'`).Scan(&events); err != nil || events != 1 {
		t.Fatalf("expiry audit %d %v", events, err)
	}
	assertPeriod(t, p, "ALL_CHAINS", 1, 0)
}

func TestSigningPostSignExpiryAndClaimFence(t *testing.T) {
	p, admitter, input, _ := limits(t, 3, 3, 3)
	admitted := submit(t, admitter, key(7), input, now)
	signer, addr := signerFixture(t)
	signer.started = make(chan struct{}, 1)
	signer.release = make(chan struct{})
	var current atomic.Int64
	current.Store(now.Add(time.Second).Unix())
	svc := issuanceFixture(t, p, signer, addr, func() time.Time { return time.Unix(current.Load(), 0).UTC() })
	result := make(chan issuance.Reason, 1)
	done := make(chan error, 1)
	go func() { _, r, e := svc.Issue(context.Background(), admitted.SponsorshipID); result <- r; done <- e }()
	<-signer.started
	current.Store(admitted.ValidUntil.Unix())
	close(signer.release)
	if reason, err := <-result, <-done; reason != issuance.AuthorizationExpired || err != nil {
		t.Fatalf("expired during signing: %s %v", reason, err)
	}
	if signer.calls.Load() != 1 {
		t.Fatal("signer not reached")
	}
	raw, _ := hex.DecodeString(admitted.SponsorshipID)
	var id [32]byte
	copy(id[:], raw)
	artifact, err := p.ReadAuthorization(context.Background(), id)
	if err != nil || artifact != nil {
		t.Fatalf("late artifact %v %v", artifact, err)
	}
}

func TestUnsignedExpiryRacesSignerReturn(t *testing.T) {
	p, admitter, input, _ := limits(t, 3, 3, 3)
	admitted := submit(t, admitter, key(14), input, now)
	signer, addr := signerFixture(t)
	signer.started = make(chan struct{}, 1)
	signer.release = make(chan struct{})
	var current atomic.Int64
	current.Store(now.Add(time.Second).Unix())
	svc := issuanceFixture(t, p, signer, addr, func() time.Time { return time.Unix(current.Load(), 0).UTC() })
	result := make(chan issuance.Reason, 1)
	failure := make(chan error, 1)
	go func() {
		_, reason, err := svc.Issue(context.Background(), admitted.SponsorshipID)
		result <- reason
		failure <- err
	}()
	<-signer.started
	count, err := p.ExpireReservations(context.Background(), admitted.ValidUntil, 10)
	if err != nil || count != 1 {
		t.Fatalf("unsigned expiry: %d %v", count, err)
	}
	current.Store(admitted.ValidUntil.Unix())
	close(signer.release)
	reason, err := <-result, <-failure
	if err != nil || reason != issuance.AuthorizationExpired {
		t.Fatalf("late signature: %s %v", reason, err)
	}
	assertPeriod(t, p, "ALL_CHAINS", 0, 0)
	raw, _ := hex.DecodeString(admitted.SponsorshipID)
	var id [32]byte
	copy(id[:], raw)
	artifact, err := p.ReadAuthorization(context.Background(), id)
	if err != nil || artifact != nil {
		t.Fatalf("late artifact: %v %v", artifact, err)
	}
}

type failBeforeCommit struct {
	issuance.Repository
	captured [32]byte
}

func (r *failBeforeCommit) CommitAuthorization(_ context.Context, _ issuance.Claim, a issuance.Artifact, _ time.Time) (issuance.Reason, error) {
	r.captured = a.Digest
	return "", errors.New("simulated process stop before artifact commit")
}

func TestCrashAfterSignatureBeforeCommit(t *testing.T) {
	p, admitter, input, _ := limits(t, 3, 3, 3)
	admitted := submit(t, admitter, key(8), input, now)
	signer, addr := signerFixture(t)
	interrupted := &failBeforeCommit{Repository: p}
	current := now.Add(time.Second)
	first, err := issuance.NewService(issuanceConfig(addr), interrupted, signer, func() time.Time { return current })
	if err != nil {
		t.Fatal(err)
	}
	_, reason, err := first.Issue(context.Background(), admitted.SponsorshipID)
	if reason != issuance.StorageUnavailable || err == nil || interrupted.captured == [32]byte{} {
		t.Fatalf("missing interrupted commit: %s %v", reason, err)
	}
	current = now.Add(22 * time.Second)
	recovered := issuanceFixture(t, p, signer, addr, func() time.Time { return current })
	artifact, reason, err := recovered.Issue(context.Background(), admitted.SponsorshipID)
	if err != nil || reason != issuance.Issued || artifact.Digest != interrupted.captured || !artifact.ValidUntil.Equal(admitted.ValidUntil) {
		t.Fatalf("recovered digest %s %v", reason, err)
	}
	if signer.calls.Load() != 2 {
		t.Fatalf("retry signer calls=%d", signer.calls.Load())
	}
	assertPeriod(t, p, "ALL_CHAINS", 1, 0)
}

func TestInterruptedSignerCallRecoversAfterLease(t *testing.T) {
	p, admitter, input, _ := limits(t, 3, 3, 3)
	admitted := submit(t, admitter, key(16), input, now)
	signer, addr := signerFixture(t)
	signer.started = make(chan struct{}, 1)
	signer.release = make(chan struct{})
	first := issuanceFixture(t, p, signer, addr, func() time.Time { return now.Add(time.Second) })
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan issuance.Reason, 1)
	go func() { _, reason, _ := first.Issue(ctx, admitted.SponsorshipID); result <- reason }()
	<-signer.started
	cancel()
	<-result
	raw, _ := hex.DecodeString(admitted.SponsorshipID)
	var id [32]byte
	copy(id[:], raw)
	artifact, err := p.ReadAuthorization(context.Background(), id)
	if err != nil || artifact != nil {
		t.Fatalf("artifact after interrupted signer: %v %v", artifact, err)
	}
	close(signer.release)
	recovered := issuanceFixture(t, p, signer, addr, func() time.Time { return now.Add(22 * time.Second) })
	issued, reason, err := recovered.Issue(context.Background(), admitted.SponsorshipID)
	if err != nil || reason != issuance.Issued || issued.SponsorshipID != id || !issued.ValidUntil.Equal(admitted.ValidUntil) {
		t.Fatalf("recovered interrupted call: %s %v", reason, err)
	}
	if signer.calls.Load() != 2 {
		t.Fatalf("signer calls after recovery: %d", signer.calls.Load())
	}
}

func TestSignerIdentityAndSignatureFailures(t *testing.T) {
	for _, mode := range []string{"reported_address", "wrong_key", "wrong_v", "high_s"} {
		t.Run(mode, func(t *testing.T) {
			p, admitter, input, _ := limits(t, 3, 3, 3)
			admitted := submit(t, admitter, key(9), input, now)
			signer, expected := signerFixture(t)
			var scalar [32]byte
			scalar[31] = 2
			otherKey, _ := crypto.ToECDSA(scalar[:])
			otherDev, _ := signing.NewDevLocalSigner(otherKey, true)
			otherAddress, _ := otherDev.Address(context.Background())
			switch mode {
			case "reported_address":
				signer.addressOverride = &otherAddress
			case "wrong_key":
				signer.delegate = otherDev
				signer.addressOverride = &expected
			case "wrong_v":
				signer.fault = "wrong_v"
			case "high_s":
				signer.fault = "high_s"
			}
			svc := issuanceFixture(t, p, signer, expected, func() time.Time { return now.Add(time.Second) })
			_, reason, err := svc.Issue(context.Background(), admitted.SponsorshipID)
			want := issuance.InvalidSignature
			if mode == "reported_address" {
				want = issuance.SignerIdentityMismatch
			}
			if err != nil || reason != want {
				t.Fatalf("%s: %s %v", mode, reason, err)
			}
		})
	}
}

func TestIssuanceProfileCannotChangeWithinPolicyVersion(t *testing.T) {
	p, admitter, input, _ := limits(t, 3, 3, 3)
	admitted := submit(t, admitter, key(10), input, now)
	signer, addr := signerFixture(t)
	original := issuanceConfig(addr).Profile()
	raw, _ := hex.DecodeString(admitted.SponsorshipID)
	var id [32]byte
	copy(id[:], raw)
	claim, err := p.ClaimSigning(context.Background(), id, original, now.Add(time.Second), 10*time.Second)
	if err != nil || claim.Reason != issuance.Issued {
		t.Fatalf("original profile %s %v", claim.Reason, err)
	}
	changed := original
	changed.Paymaster[0] ^= 1
	other, err := p.ClaimSigning(context.Background(), id, changed, now.Add(11*time.Second), 10*time.Second)
	if err != nil || other.Reason != issuance.PolicyVersionConflict {
		t.Fatalf("changed profile %s %v", other.Reason, err)
	}
	if err = p.FailSigningClaim(context.Background(), claim.Claim, issuance.SignerUnavailable, now.Add(12*time.Second)); err != nil {
		t.Fatal(err)
	}
	svc := issuanceFixture(t, p, signer, addr, func() time.Time { return now.Add(13 * time.Second) })
	_, reason, err := svc.Issue(context.Background(), admitted.SponsorshipID)
	if err != nil || reason != issuance.Issued {
		t.Fatalf("original profile retry %s %v", reason, err)
	}
}

func TestIssuanceProfileBoundBeforeFirstClaim(t *testing.T) {
	p, admitter, input, amount := limits(t, 3, 3, 3)
	admitted := submit(t, admitter, key(31), input, now)
	policyJSON, err := os.ReadFile("../../config/policy.example.json")
	if err != nil {
		t.Fatal(err)
	}
	changedProfile := testIssuerProfileConfig()
	changedProfile.Paymaster = "0x4444444444444444444444444444444444444444"
	changedConfig := admission.Config{
		NativeAsset: "ETH", GlobalDailyBudgetWei: multiplied(amount, 3),
		Chains:           []admission.ChainLimit{{ChainID: chain, NativeAsset: "ETH", DailyBudgetWei: multiplied(amount, 3), SenderDailyWei: multiplied(amount, 200), SenderDailyCount: 3}},
		IssuanceProfiles: []admission.IssuerProfileConfig{changedProfile},
	}
	changedAdmitter, err := admission.NewService(policyJSON, changedConfig, p)
	if err != nil {
		t.Fatal(err)
	}
	otherInput := input
	otherInput.Nonce = "8"
	other, admissionErr := changedAdmitter.Admit(context.Background(), "client-a", key(32), otherInput, now)
	if !errors.Is(admissionErr, admission.ErrPolicyVersionConflict) || other.Reason != admission.PolicyVersionConflict {
		t.Fatalf("same-version profile changed: %+v %v", other, admissionErr)
	}
	requests, reservations := counts(t, p)
	if requests != 1 || reservations != 1 {
		t.Fatalf("changed profile affected ledger: %d/%d", requests, reservations)
	}
	signer, addr := signerFixture(t)
	changed := issuanceConfig(addr)
	changed.Paymaster[0] ^= 1
	wrong, err := issuance.NewService(changed, p, signer, func() time.Time { return now.Add(time.Second) })
	if err != nil {
		t.Fatal(err)
	}
	_, reason, err := wrong.Issue(context.Background(), admitted.SponsorshipID)
	if err != nil || reason != issuance.PolicyVersionConflict || signer.calls.Load() != 0 {
		t.Fatalf("first claim changed profile: %s %v", reason, err)
	}
	var profiles, claims int
	if err = p.Pool().QueryRow(context.Background(), `SELECT count(*) FROM issuance_profiles WHERE policy_version=1 AND chain_id=$1::numeric`, chain).Scan(&profiles); err != nil || profiles != 1 {
		t.Fatalf("published profiles=%d %v", profiles, err)
	}
	if err = p.Pool().QueryRow(context.Background(), `SELECT count(*) FROM sponsorship_reservations WHERE signing_claim_token IS NOT NULL`).Scan(&claims); err != nil || claims != 0 {
		t.Fatalf("unexpected claims=%d %v", claims, err)
	}
	original := issuanceFixture(t, p, signer, addr, func() time.Time { return now.Add(2 * time.Second) })
	_, reason, err = original.Issue(context.Background(), admitted.SponsorshipID)
	if err != nil || reason != issuance.Issued || signer.calls.Load() != 1 {
		t.Fatalf("original profile: %s %v", reason, err)
	}
}

func TestWrongChainIssuerCannotClaimReservation(t *testing.T) {
	p, admitter, input, _ := limits(t, 3, 3, 3)
	admitted := submit(t, admitter, key(15), input, now)
	signer, addr := signerFixture(t)
	config := issuanceConfig(addr)
	other, _ := policy.ParseUint256("31338")
	config.ChainID = policy.ChainID{Uint256: other}
	svc, err := issuance.NewService(config, p, signer, func() time.Time { return now.Add(time.Second) })
	if err != nil {
		t.Fatal(err)
	}
	_, reason, err := svc.Issue(context.Background(), admitted.SponsorshipID)
	if err != nil || reason != issuance.PolicyVersionConflict || signer.calls.Load() != 0 {
		t.Fatalf("cross-chain issuer: %s %v", reason, err)
	}
	var count int
	if err = p.Pool().QueryRow(context.Background(), `SELECT count(*) FROM issuance_profiles`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("wrong-chain profile count %d %v", count, err)
	}
}

func TestArtifactFieldsImmutable(t *testing.T) {
	p, admitter, input, _ := limits(t, 3, 3, 3)
	admitted := submit(t, admitter, key(11), input, now)
	signer, addr := signerFixture(t)
	svc := issuanceFixture(t, p, signer, addr, func() time.Time { return now.Add(time.Second) })
	_, reason, err := svc.Issue(context.Background(), admitted.SponsorshipID)
	if err != nil || reason != issuance.Issued {
		t.Fatalf("issue %s %v", reason, err)
	}
	raw, _ := hex.DecodeString(admitted.SponsorshipID)
	_, err = p.Pool().Exec(context.Background(), `UPDATE sponsorship_reservations SET signature=decode(repeat('00',65),'hex') WHERE sponsorship_id=$1`, raw)
	if err == nil {
		t.Fatal("issued signature was mutable")
	}
	_, err = p.Pool().Exec(context.Background(), `UPDATE issuance_profiles SET paymaster_address=decode(repeat('44',20),'hex') WHERE policy_version=1`)
	if err == nil {
		t.Fatal("issuance profile was mutable")
	}
}

func TestRetryAfterPolicyUpdateKeepsOriginalApproval(t *testing.T) {
	p, original, input, amount := limits(t, 3, 3, 3)
	admitted := submit(t, original, key(12), input, now)
	base, err := os.ReadFile("../../config/policy.example.json")
	if err != nil {
		t.Fatal(err)
	}
	updated := []byte(strings.Replace(string(base), `"version": 1`, `"version": 2`, 1))
	if string(updated) == string(base) {
		t.Fatal("policy version fixture did not change")
	}
	config := admission.Config{NativeAsset: "ETH", GlobalDailyBudgetWei: multiplied(amount, 3), Chains: []admission.ChainLimit{{ChainID: chain, NativeAsset: "ETH", DailyBudgetWei: multiplied(amount, 3), SenderDailyWei: multiplied(amount, 3), SenderDailyCount: 3}}}
	newAdmission, err := admission.NewService(updated, config, p)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := newAdmission.Admit(context.Background(), "client-a", key(12), input, now.Add(time.Second))
	if err != nil || !retry.Replayed || retry.PolicyVersion != 1 || retry.SponsorshipID != admitted.SponsorshipID {
		t.Fatalf("original request lost: %+v %v", retry, err)
	}
	signer, addr := signerFixture(t)
	newConfig := issuanceConfig(addr)
	newConfig.PolicyVersion = 2
	newIssuer, err := issuance.NewService(newConfig, p, signer, func() time.Time { return now.Add(time.Second) })
	if err != nil {
		t.Fatal(err)
	}
	_, reason, err := newIssuer.Issue(context.Background(), admitted.SponsorshipID)
	if err != nil || reason != issuance.PolicyVersionConflict || signer.calls.Load() != 0 {
		t.Fatalf("new issuer %s %v", reason, err)
	}
	oldIssuer := issuanceFixture(t, p, signer, addr, func() time.Time { return now.Add(2 * time.Second) })
	artifact, reason, err := oldIssuer.Issue(context.Background(), admitted.SponsorshipID)
	if err != nil || reason != issuance.Issued || artifact.PolicyVersion != 1 {
		t.Fatalf("old issuer %s %v", reason, err)
	}
}

func TestSignerTimeoutLeavesReservationRetryable(t *testing.T) {
	p, admitter, input, _ := limits(t, 3, 3, 3)
	admitted := submit(t, admitter, key(13), input, now)
	signer, addr := signerFixture(t)
	signer.release = make(chan struct{})
	config := issuanceConfig(addr)
	config.SignerTimeout = 20 * time.Millisecond
	svc, err := issuance.NewService(config, p, signer, func() time.Time { return now.Add(time.Second) })
	if err != nil {
		t.Fatal(err)
	}
	_, reason, err := svc.Issue(context.Background(), admitted.SponsorshipID)
	if err != nil || reason != issuance.SignerTimeout {
		t.Fatalf("timeout %s %v", reason, err)
	}
	assertPeriod(t, p, "ALL_CHAINS", 1, 0)
	close(signer.release)
	recovered := issuanceFixture(t, p, signer, addr, func() time.Time { return now.Add(2 * time.Second) })
	_, reason, err = recovered.Issue(context.Background(), admitted.SponsorshipID)
	if err != nil || reason != issuance.Issued {
		t.Fatalf("retry %s %v", reason, err)
	}
}

func TestSignerResponseAfterDeadlineIsDiscarded(t *testing.T) {
	p, admitter, input, _ := limits(t, 3, 3, 3)
	admitted := submit(t, admitter, key(33), input, now)
	signer, addr := signerFixture(t)
	signer.fault = "ignore_timeout"
	config := issuanceConfig(addr)
	config.SignerTimeout = 10 * time.Millisecond
	svc, err := issuance.NewService(config, p, signer, func() time.Time { return now.Add(time.Second) })
	if err != nil {
		t.Fatal(err)
	}
	_, reason, err := svc.Issue(context.Background(), admitted.SponsorshipID)
	if err != nil || reason != issuance.SignerTimeout {
		t.Fatalf("late signer response: %s %v", reason, err)
	}
	var count int
	if err = p.Pool().QueryRow(context.Background(), `SELECT count(*) FROM sponsorship_reservations WHERE signed_artifact IS NOT NULL`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("late artifact count=%d %v", count, err)
	}
	signer.fault = ""
	_, reason, err = svc.Issue(context.Background(), admitted.SponsorshipID)
	if err != nil || reason != issuance.Issued {
		t.Fatalf("retry after late response: %s %v", reason, err)
	}
}
