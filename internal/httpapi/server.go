package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/demo-lenoir/gasless-policy-engine/internal/admission"
	"github.com/demo-lenoir/gasless-policy-engine/internal/issuance"
	"github.com/demo-lenoir/gasless-policy-engine/internal/policy"
	"github.com/demo-lenoir/gasless-policy-engine/internal/reconcile"
	"github.com/demo-lenoir/gasless-policy-engine/internal/store"
	"go.opentelemetry.io/otel"
)

const maxBodyBytes = 300 * 1024

type Admission interface {
	Admit(context.Context, string, string, policy.RequestInput, time.Time) (admission.Result, error)
}
type Issuer interface {
	Issue(context.Context, string) (issuance.Artifact, issuance.Reason, error)
}
type Repository interface {
	ReadSponsorship(context.Context, string, string) (*store.SponsorshipView, error)
	ReadOperationalState(context.Context, string, time.Time) (store.OperationalState, error)
	Checkpoint(context.Context, reconcile.Stream) (reconcile.Checkpoint, error)
}
type Server struct {
	Admitter Admission
	Issuer   Issuer
	Store    Repository
	Stream   reconcile.Stream
	Reader   reconcile.Reader
	Watcher  interface{ Readiness(context.Context) error }
	Signer   interface {
		Address(context.Context) (policy.Address, error)
	}
	ExpectedSigner     policy.Address
	Deposit            func(context.Context) (string, error)
	DepositLowWei      string
	DepositCriticalWei string
	AuthToken          string
	ClientScope        string
	Now                func() time.Time
	Metrics            http.Handler
	Logger             *slog.Logger
}

type request struct {
	ChainID       string `json:"chain_id"`
	EntryPoint    string `json:"entry_point"`
	UserOperation struct {
		Sender                        string `json:"sender"`
		Nonce                         string `json:"nonce"`
		CallData                      string `json:"call_data"`
		CallGasLimit                  string `json:"call_gas_limit"`
		VerificationGasLimit          string `json:"verification_gas_limit"`
		PreVerificationGas            string `json:"pre_verification_gas"`
		MaxFeePerGas                  string `json:"max_fee_per_gas"`
		MaxPriorityFeePerGas          string `json:"max_priority_fee_per_gas"`
		PaymasterVerificationGasLimit string `json:"paymaster_verification_gas_limit"`
		PaymasterPostOpGasLimit       string `json:"paymaster_post_op_gas_limit"`
	} `json:"user_operation"`
	RequestedLifetimeSeconds string `json:"requested_lifetime_seconds,omitempty"`
}

func (r request) input() policy.RequestInput {
	u := r.UserOperation
	return policy.RequestInput{ChainID: r.ChainID, EntryPoint: r.EntryPoint, Sender: u.Sender, Nonce: u.Nonce, CallData: u.CallData, CallGasLimit: u.CallGasLimit, VerificationGasLimit: u.VerificationGasLimit, PreVerificationGas: u.PreVerificationGas, MaxFeePerGas: u.MaxFeePerGas, MaxPriorityFeePerGas: u.MaxPriorityFeePerGas, PaymasterVerificationGasLimit: u.PaymasterVerificationGasLimit, PaymasterPostOpGasLimit: u.PaymasterPostOpGasLimit, RequestedLifetimeSeconds: r.RequestedLifetimeSeconds}
}

type response struct {
	RequestID              string                 `json:"request_id"`
	Decision               string                 `json:"decision"`
	Reason                 string                 `json:"reason"`
	PolicyVersion          policy.PolicyVersion   `json:"policy_version,omitempty"`
	SponsorshipID          string                 `json:"sponsorship_id,omitempty"`
	ValidAfter             *time.Time             `json:"valid_after,omitempty"`
	ValidUntil             *time.Time             `json:"valid_until,omitempty"`
	UserOpHash             string                 `json:"user_op_hash,omitempty"`
	EstimatedUpperBoundWei string                 `json:"estimated_upper_bound_wei,omitempty"`
	Authorization          *authorizationResponse `json:"authorization,omitempty"`
}
type authorizationResponse struct {
	Paymaster                     string `json:"paymaster"`
	PaymasterVerificationGasLimit string `json:"paymaster_verification_gas_limit"`
	PaymasterPostOpGasLimit       string `json:"paymaster_post_op_gas_limit"`
	PaymasterAndData              string `json:"paymaster_and_data"`
}
type apiError struct {
	RequestID string `json:"request_id"`
	Code      string `json:"code"`
	Message   string `json:"message"`
}

func (s *Server) Handler() (http.Handler, error) {
	if s.Admitter == nil || s.Issuer == nil || s.Store == nil || s.Reader == nil || s.Watcher == nil || s.Signer == nil || s.Deposit == nil || s.AuthToken == "" || s.ClientScope == "" || s.Now == nil || s.Logger == nil || s.Stream.Validate() != nil || s.ExpectedSigner.IsZero() {
		return nil, errors.New("incomplete HTTP service dependencies")
	}
	low, err := policy.ParseUint256(s.DepositLowWei)
	if err != nil || low.IsZero() {
		return nil, errors.New("invalid low deposit threshold")
	}
	critical, err := policy.ParseUint256(s.DepositCriticalWei)
	if err != nil || critical.IsZero() || critical.Cmp(low) >= 0 {
		return nil, errors.New("invalid critical deposit threshold")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/sponsorships", s.wrap(true, s.create))
	mux.HandleFunc("GET /v1/sponsorships/{id}", s.wrap(true, s.read))
	mux.HandleFunc("GET /v1/status", s.wrap(true, s.status))
	mux.HandleFunc("GET /health/live", s.wrap(false, func(w http.ResponseWriter, r *http.Request, id string) {
		writeJSON(w, 200, map[string]any{"status": "live", "request_id": id})
	}))
	mux.HandleFunc("GET /health/ready", s.wrap(false, s.ready))
	if s.Metrics != nil {
		mux.Handle("GET /metrics", s.Metrics)
	}
	return mux, nil
}

func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("system entropy unavailable")
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
}
func (s *Server) wrap(auth bool, next func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := newID()
		name := r.Pattern
		if name == "" {
			name = r.Method
		}
		ctx, span := otel.Tracer("gasless/http").Start(r.Context(), name)
		defer span.End()
		r = r.WithContext(ctx)
		w.Header().Set("X-Request-ID", id)
		if auth {
			value := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if len(value) != len(s.AuthToken) || subtle.ConstantTimeCompare([]byte(value), []byte(s.AuthToken)) != 1 {
				failure(w, 401, id, "UNAUTHORIZED", "Authentication required")
				return
			}
		}
		next(w, r, id)
	}
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func failure(w http.ResponseWriter, status int, id, code, message string) {
	writeJSON(w, status, apiError{id, code, message})
}

func (s *Server) create(w http.ResponseWriter, r *http.Request, id string) {
	if state, err := s.inspect(r.Context()); err != nil || !state.Ready {
		failure(w, 503, id, "NOT_READY", "Sponsorship issuance unavailable")
		return
	}
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		failure(w, 400, id, "INVALID_REQUEST", "JSON body required")
		return
	}
	key := r.Header.Get("Idempotency-Key")
	if len(key) < 16 || len(key) > 128 {
		failure(w, 400, id, "INVALID_REQUEST", "Invalid idempotency key")
		return
	}
	for _, c := range key {
		if c < 33 || c > 126 {
			failure(w, 400, id, "INVALID_REQUEST", "Invalid idempotency key")
			return
		}
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil || admission.RejectDuplicateKeys(data) != nil {
		failure(w, 400, id, "INVALID_REQUEST", "Malformed JSON body")
		return
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var input request
	if dec.Decode(&input) != nil || dec.Decode(new(any)) != io.EOF {
		failure(w, 400, id, "INVALID_REQUEST", "Malformed JSON body")
		return
	}
	result, err := s.Admitter.Admit(r.Context(), s.ClientScope, key, input.input(), s.Now().UTC())
	if err != nil {
		failure(w, 503, id, "DEPENDENCY_UNAVAILABLE", "Sponsorship unavailable")
		s.Logger.Error("admission failed", "request_id", id)
		return
	}
	if result.Reason == admission.IdempotencyConflict {
		failure(w, 409, id, "IDEMPOTENCY_CONFLICT", "Idempotency key conflicts with stored request")
		return
	}
	if !result.Approved {
		reason := string(result.Reason)
		if result.Reason == admission.StaticPolicyDenied {
			reason = string(result.PolicyReason)
		}
		status := 422
		if result.Reason == admission.InvalidRequest || result.PolicyReason == policy.ReasonMalformedRequest || result.PolicyReason == policy.ReasonUnsupportedCallShape {
			status = 400
		}
		if result.Reason == admission.ReservationStateConflict || result.Reason == admission.ReservationExpired {
			status = 409
		}
		writeJSON(w, status, response{RequestID: id, Decision: "denied", Reason: reason, PolicyVersion: result.PolicyVersion, SponsorshipID: withHex(result.SponsorshipID)})
		s.Logger.Info("sponsorship denied", "request_id", id, "reason", reason)
		return
	}
	issueCtx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	artifact, reason, err := s.Issuer.Issue(issueCtx, result.SponsorshipID)
	cancel()
	if reason == issuance.SigningInProgress && r.Context().Err() == nil {
		w.Header().Set("Retry-After", "1")
		writeJSON(w, 202, response{RequestID: id, Decision: "pending", Reason: string(reason), PolicyVersion: result.PolicyVersion, SponsorshipID: withHex(result.SponsorshipID)})
		return
	}
	if err != nil || reason == issuance.StorageUnavailable || reason == issuance.SignerUnavailable || reason == issuance.SignerTimeout || reason == issuance.SignerIdentityMismatch || reason == issuance.InvalidSignature {
		failure(w, 503, id, "DEPENDENCY_UNAVAILABLE", "Authorization unavailable")
		s.Logger.Error("issuance failed", "request_id", id, "reason", reason)
		return
	}
	if reason != issuance.Issued && reason != issuance.AlreadyIssued {
		failure(w, 409, id, "AUTHORIZATION_STATE_CONFLICT", "Authorization cannot be issued")
		return
	}
	view, err := s.Store.ReadSponsorship(r.Context(), s.ClientScope, result.SponsorshipID)
	if err != nil || view == nil || view.UserOpHash == "" {
		failure(w, 503, id, "DEPENDENCY_UNAVAILABLE", "Authorization state unavailable")
		return
	}
	paymasterGas := new(big.Int).SetBytes(artifact.PaymasterAndData[20:36]).String()
	validAfter, validUntil := artifact.ValidAfter, artifact.ValidUntil
	out := response{RequestID: id, Decision: "approved", Reason: "APPROVED", PolicyVersion: artifact.PolicyVersion, SponsorshipID: withHex(result.SponsorshipID), ValidAfter: &validAfter, ValidUntil: &validUntil, UserOpHash: view.UserOpHash, EstimatedUpperBoundWei: result.EstimatedUpperBoundWei, Authorization: &authorizationResponse{Paymaster: artifact.Paymaster.String(), PaymasterVerificationGasLimit: paymasterGas, PaymasterPostOpGasLimit: "0", PaymasterAndData: "0x" + hex.EncodeToString(artifact.PaymasterAndData[:])}}
	status := 201
	if result.Replayed || reason == issuance.AlreadyIssued {
		status = 200
	}
	writeJSON(w, status, out)
	s.Logger.Info("sponsorship approved", "request_id", id, "sponsorship_id", out.SponsorshipID)
}
func withHex(id string) string {
	if id == "" {
		return ""
	}
	return "0x" + id
}

func (s *Server) read(w http.ResponseWriter, r *http.Request, id string) {
	sponsorshipID := strings.TrimPrefix(r.PathValue("id"), "0x")
	if len(sponsorshipID) != 64 {
		failure(w, 400, id, "INVALID_REQUEST", "Invalid sponsorship ID")
		return
	}
	if _, err := hex.DecodeString(sponsorshipID); err != nil {
		failure(w, 400, id, "INVALID_REQUEST", "Invalid sponsorship ID")
		return
	}
	view, err := s.Store.ReadSponsorship(r.Context(), s.ClientScope, sponsorshipID)
	if err != nil {
		failure(w, 503, id, "DEPENDENCY_UNAVAILABLE", "Sponsorship state unavailable")
		return
	}
	if view == nil {
		failure(w, 404, id, "NOT_FOUND", "Sponsorship not found")
		return
	}
	writeJSON(w, 200, view)
}

type statusView struct {
	ChainID             string                 `json:"chain_id"`
	EntryPoint          string                 `json:"entry_point"`
	Paymaster           string                 `json:"paymaster"`
	Checkpoint          uint64                 `json:"checkpoint"`
	ObservedHead        uint64                 `json:"observed_head"`
	LagBlocks           uint64                 `json:"lag_blocks"`
	StreamState         string                 `json:"stream_state"`
	Accounting          store.OperationalState `json:"accounting"`
	PaymasterDepositWei string                 `json:"paymaster_deposit_wei"`
	DepositState        string                 `json:"deposit_state"`
	SignerAvailable     bool                   `json:"signer_available"`
	Ready               bool                   `json:"ready"`
	UnsafeReason        string                 `json:"unsafe_reason,omitempty"`
}

func (s *Server) inspect(ctx context.Context) (statusView, error) {
	v := statusView{ChainID: s.Stream.ChainID.String(), EntryPoint: s.Stream.EntryPoint.String(), Paymaster: s.Stream.Paymaster.String(), StreamState: "UNAVAILABLE", DepositState: "unknown"}
	state, err := s.Store.ReadOperationalState(ctx, s.Stream.ChainID.String(), s.Now().UTC())
	if err != nil {
		return v, err
	}
	v.Accounting = state
	cp, err := s.Store.Checkpoint(ctx, s.Stream)
	if err != nil {
		return v, err
	}
	if cp.Exists {
		v.Checkpoint = cp.Number
		v.StreamState = cp.State
	}
	if err = s.Watcher.Readiness(ctx); err != nil {
		v.UnsafeReason = "RECONCILIATION_UNAVAILABLE"
	}
	head, err := s.Reader.HeaderByNumber(ctx, nil)
	if err != nil || head == nil || !head.Number.IsUint64() {
		if v.UnsafeReason == "" {
			v.UnsafeReason = "CHAIN_UNAVAILABLE"
		}
	} else {
		v.ObservedHead = head.Number.Uint64()
		if v.ObservedHead >= v.Checkpoint {
			v.LagBlocks = v.ObservedHead - v.Checkpoint
		}
		if v.LagBlocks > s.Stream.MaxBlocks && v.UnsafeReason == "" {
			v.UnsafeReason = "RECONCILIATION_LAG"
		}
	}
	address, err := s.Signer.Address(ctx)
	if err == nil && address == s.ExpectedSigner {
		v.SignerAvailable = true
	} else if v.UnsafeReason == "" {
		v.UnsafeReason = "SIGNER_UNAVAILABLE"
	}
	v.PaymasterDepositWei, err = s.Deposit(ctx)
	if err != nil {
		if v.UnsafeReason == "" {
			v.UnsafeReason = "DEPOSIT_UNAVAILABLE"
		}
	} else {
		deposit, parseErr := policy.ParseUint256(v.PaymasterDepositWei)
		if parseErr != nil {
			if v.UnsafeReason == "" {
				v.UnsafeReason = "DEPOSIT_UNAVAILABLE"
			}
		} else {
			v.DepositState = "healthy"
			low, _ := policy.ParseUint256(s.DepositLowWei)
			critical, _ := policy.ParseUint256(s.DepositCriticalWei)
			if deposit.Cmp(critical) < 0 {
				v.DepositState = "critical"
			} else if deposit.Cmp(low) < 0 {
				v.DepositState = "low"
			}
		}
	}
	if !state.AccountingValid && v.UnsafeReason == "" {
		v.UnsafeReason = "ACCOUNTING_INVARIANT"
	}
	if state.EmergencyDisabled && v.UnsafeReason == "" {
		v.UnsafeReason = "EMERGENCY_DISABLED"
	}
	if v.DepositState == "critical" && v.UnsafeReason == "" {
		v.UnsafeReason = "DEPOSIT_CRITICAL"
	}
	v.Ready = v.UnsafeReason == "" && v.DepositState != "unknown"
	return v, nil
}
func (s *Server) status(w http.ResponseWriter, r *http.Request, id string) {
	v, err := s.inspect(r.Context())
	if err != nil {
		failure(w, 503, id, "DEPENDENCY_UNAVAILABLE", "Operational status unavailable")
		return
	}
	writeJSON(w, 200, v)
}
func (s *Server) ready(w http.ResponseWriter, r *http.Request, id string) {
	v, err := s.inspect(r.Context())
	if err != nil || !v.Ready {
		failure(w, 503, id, "NOT_READY", "Service is not ready")
		return
	}
	writeJSON(w, 200, map[string]any{"status": "ready", "request_id": id})
}
