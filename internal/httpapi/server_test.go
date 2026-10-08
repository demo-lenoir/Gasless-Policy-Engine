package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/demo-lenoir/gasless-policy-engine/internal/admission"
	"github.com/demo-lenoir/gasless-policy-engine/internal/issuance"
	"github.com/demo-lenoir/gasless-policy-engine/internal/policy"
	"github.com/demo-lenoir/gasless-policy-engine/internal/reconcile"
	"github.com/demo-lenoir/gasless-policy-engine/internal/store"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

const fixtureID = "1111111111111111111111111111111111111111111111111111111111111111"
const fixtureBody = `{"chain_id":"31337","entry_point":"0x1111111111111111111111111111111111111111","user_operation":{"sender":"0x2222222222222222222222222222222222222222","nonce":"0","call_data":"0x12345678","call_gas_limit":"1","verification_gas_limit":"1","pre_verification_gas":"1","max_fee_per_gas":"1","max_priority_fee_per_gas":"1","paymaster_verification_gas_limit":"1","paymaster_post_op_gas_limit":"0"}}`

type fakeAdmission struct {
	mu           sync.Mutex
	fingerprints map[string]string
}

func (f *fakeAdmission) Admit(_ context.Context, _, key string, input policy.RequestInput, _ time.Time) (admission.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fingerprints == nil {
		f.fingerprints = map[string]string{}
	}
	if old, ok := f.fingerprints[key]; ok {
		if old != input.CallData {
			return admission.Result{Reason: admission.IdempotencyConflict}, nil
		}
		return admission.Result{Approved: true, Reason: admission.Approved, SponsorshipID: fixtureID, PolicyVersion: 1, Replayed: true}, nil
	}
	f.fingerprints[key] = input.CallData
	return admission.Result{Approved: true, Reason: admission.Approved, SponsorshipID: fixtureID, PolicyVersion: 1}, nil
}

type fakeIssuer struct {
	mu       sync.Mutex
	calls    int
	artifact issuance.Artifact
}

func (f *fakeIssuer) Issue(context.Context, string) (issuance.Artifact, issuance.Reason, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.calls == 1 {
		return f.artifact, issuance.Issued, nil
	}
	return f.artifact, issuance.AlreadyIssued, nil
}

type fakeStore struct{ state store.OperationalState }

func (f fakeStore) ReadSponsorship(_ context.Context, scope, id string) (*store.SponsorshipView, error) {
	if scope != "client" || id != fixtureID {
		return nil, nil
	}
	return &store.SponsorshipView{SponsorshipID: "0x" + id, UserOpHash: "0x" + strings.Repeat("2", 64)}, nil
}
func (f fakeStore) ReadOperationalState(context.Context, string, time.Time) (store.OperationalState, error) {
	return f.state, nil
}
func (f fakeStore) Checkpoint(context.Context, reconcile.Stream) (reconcile.Checkpoint, error) {
	return reconcile.Checkpoint{Exists: true, State: "HEALTHY", Number: 5}, nil
}

type fakeReader struct{}

func (fakeReader) ChainID(context.Context) (*big.Int, error) { return big.NewInt(31337), nil }
func (fakeReader) CodeAt(context.Context, common.Address, *big.Int) ([]byte, error) {
	return []byte{1}, nil
}
func (fakeReader) HeaderByNumber(context.Context, *big.Int) (*types.Header, error) {
	return &types.Header{Number: big.NewInt(5)}, nil
}
func (fakeReader) FilterLogs(context.Context, ethereum.FilterQuery) ([]types.Log, error) {
	return nil, nil
}

type fakeWatcher struct{ err error }

func (f fakeWatcher) Readiness(context.Context) error { return f.err }

type fakeSigner struct{ address policy.Address }

func (f fakeSigner) Address(context.Context) (policy.Address, error) { return f.address, nil }

func testServer(t *testing.T) (http.Handler, *fakeIssuer, *fakeAdmission) {
	t.Helper()
	chainValue, _ := policy.ParseUint256("31337")
	address, _ := policy.ParseAddress("0x1111111111111111111111111111111111111111")
	issuer := &fakeIssuer{artifact: issuance.Artifact{PolicyVersion: 1, Paymaster: address, ValidAfter: time.Unix(1, 0), ValidUntil: time.Unix(61, 0)}}
	admitter := &fakeAdmission{}
	server := &Server{Admitter: admitter, Issuer: issuer, Store: fakeStore{state: store.OperationalState{AccountingValid: true}}, Stream: reconcile.Stream{ChainID: policy.ChainID{Uint256: chainValue}, EntryPoint: address, Paymaster: address, ID: "test", Confirmations: 3, MaxReorgDepth: 8, MaxBlocks: 100}, Reader: fakeReader{}, Watcher: fakeWatcher{}, Signer: fakeSigner{address}, ExpectedSigner: address, Deposit: func(context.Context) (string, error) { return "1000000000000000000", nil }, DepositLowWei: "100000000000000000", DepositCriticalWei: "10000000000000000", AuthToken: "abcdefghijklmnopqrstuvwxyz012345", ClientScope: "client", Now: time.Now, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	handler, err := server.Handler()
	if err != nil {
		t.Fatal(err)
	}
	return handler, issuer, admitter
}
func post(t *testing.T, h http.Handler, key, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("POST", "/v1/sponsorships", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer abcdefghijklmnopqrstuvwxyz012345")
	r.Header.Set("Idempotency-Key", key)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestHTTPIdempotencyAndRequestBoundary(t *testing.T) {
	h, issuer, _ := testServer(t)
	for i := 0; i < 2; i++ {
		w := post(t, h, "long-idempotency-key-0001", fixtureBody)
		want := 201
		if i == 1 {
			want = 200
		}
		if w.Code != want {
			t.Fatalf("retry %d status %d: %s", i, w.Code, w.Body.String())
		}
		var response map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if response["sponsorship_id"] != "0x"+fixtureID || response["user_op_hash"] == nil {
			t.Fatal(response)
		}
	}
	changed := strings.Replace(fixtureBody, `"call_data":"0x12345678"`, `"call_data":"0x99999999"`, 1)
	if w := post(t, h, "long-idempotency-key-0001", changed); w.Code != 409 || !strings.Contains(w.Body.String(), "IDEMPOTENCY_CONFLICT") {
		t.Fatalf("conflict %d %s", w.Code, w.Body.String())
	}
	if issuer.calls != 2 {
		t.Fatalf("issuer calls: %d", issuer.calls)
	}
	for _, body := range []string{strings.Replace(fixtureBody, `"nonce":"0"`, `"nonce":"0","nonce":"1"`, 1), strings.Replace(fixtureBody, `"nonce":"0"`, `"digest":"0x00","nonce":"0"`, 1), "{"} {
		if w := post(t, h, "long-idempotency-key-0002", body); w.Code != 400 {
			t.Fatalf("malformed %d %s", w.Code, w.Body.String())
		}
	}
	r := httptest.NewRequest("POST", "/v1/sponsorships", strings.NewReader(fixtureBody))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("unauthorized %d", w.Code)
	}
}

func TestHealthAndStatus(t *testing.T) {
	h, _, _ := testServer(t)
	for _, path := range []string{"/health/live", "/health/ready"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 200 {
			t.Fatalf("%s: %d", path, w.Code)
		}
	}
	r := httptest.NewRequest("GET", "/v1/status", nil)
	r.Header.Set("Authorization", "Bearer abcdefghijklmnopqrstuvwxyz012345")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"ready":true`) {
		t.Fatalf("status %d %s", w.Code, w.Body.String())
	}
	badID := httptest.NewRequest("GET", "/v1/sponsorships/0xbroken", nil)
	badID.Header.Set("Authorization", "Bearer abcdefghijklmnopqrstuvwxyz012345")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, badID)
	if w.Code != 400 || !strings.Contains(w.Body.String(), "INVALID_REQUEST") {
		t.Fatalf("malformed sponsorship ID: %d %s", w.Code, w.Body.String())
	}
}
