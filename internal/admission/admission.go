package admission

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"sort"
	"time"

	"github.com/demo-lenoir/gasless-policy-engine/internal/policy"
	"go.opentelemetry.io/otel"
)

type Reason string

const (
	Approved                 Reason = "APPROVED_FOR_SIGNING"
	StaticPolicyDenied       Reason = "STATIC_POLICY_DENIED"
	QuotaExhausted           Reason = "QUOTA_EXHAUSTED"
	GlobalBudgetExhausted    Reason = "GLOBAL_BUDGET_EXHAUSTED"
	ChainBudgetExhausted     Reason = "CHAIN_BUDGET_EXHAUSTED"
	IdempotencyConflict      Reason = "IDEMPOTENCY_CONFLICT"
	ReservationExpired       Reason = "RESERVATION_EXPIRED"
	ReservationStateConflict Reason = "RESERVATION_STATE_CONFLICT"
	StorageUnavailable       Reason = "STORAGE_UNAVAILABLE"
	EmergencyDisabled        Reason = "EMERGENCY_DISABLED"
	PolicyVersionConflict    Reason = "POLICY_VERSION_CONFLICT"
	InvalidRequest           Reason = "INVALID_REQUEST"
)

var ErrPolicyVersionConflict = errors.New("policy version has a different published snapshot")

type Result struct {
	RequestID                string
	SponsorshipID            string
	Approved                 bool
	Reason                   Reason
	PolicyReason             policy.Reason
	PolicyVersion            policy.PolicyVersion
	Fingerprint              [32]byte
	EstimatedUpperBoundWei   string
	GlobalBudgetRemainingWei string
	ValidAfter               time.Time
	ValidUntil               time.Time
	Replayed                 bool
}

type ChainLimit struct {
	ChainID          string `json:"chain_id"`
	NativeAsset      string `json:"native_asset"`
	DailyBudgetWei   string `json:"daily_budget_wei"`
	SenderDailyWei   string `json:"sender_daily_wei"`
	SenderDailyCount int64  `json:"sender_daily_count"`
}
type Config struct {
	NativeAsset          string                `json:"native_asset"`
	GlobalDailyBudgetWei string                `json:"global_daily_budget_wei"`
	Chains               []ChainLimit          `json:"chains"`
	IssuanceProfiles     []IssuerProfileConfig `json:"issuance_profiles,omitempty"`
}
type IssuerProfileConfig struct {
	ChainID         string `json:"chain_id"`
	Paymaster       string `json:"paymaster"`
	EntryPoint      string `json:"entry_point"`
	AccountCodeHash string `json:"account_code_hash"`
	ExpectedSigner  string `json:"expected_signer"`
}
type IssuerProfile struct {
	ChainID         policy.ChainID
	Paymaster       policy.Address
	EntryPoint      policy.Address
	AccountCodeHash [32]byte
	ExpectedSigner  policy.Address
}
type Limits struct {
	Global policy.Uint256
	Chains map[policy.ChainID]ChainLimits
}
type ChainLimits struct {
	Daily, SenderDaily policy.Uint256
	SenderCount        int64
}

func NewLimits(cfg Config) (Limits, error) {
	if cfg.NativeAsset == "" || len(cfg.NativeAsset) > 32 {
		return Limits{}, errors.New("native asset identity is required")
	}
	global, err := positive(cfg.GlobalDailyBudgetWei)
	if err != nil {
		return Limits{}, fmt.Errorf("global daily budget: %w", err)
	}
	if len(cfg.Chains) == 0 {
		return Limits{}, errors.New("at least one chain budget is required")
	}
	out := Limits{Global: global, Chains: make(map[policy.ChainID]ChainLimits, len(cfg.Chains))}
	for _, c := range cfg.Chains {
		if c.NativeAsset != cfg.NativeAsset {
			return Limits{}, errors.New("chain native asset differs from global budget unit")
		}
		id, e := positive(c.ChainID)
		if e != nil {
			return Limits{}, fmt.Errorf("chain ID: %w", e)
		}
		chain := policy.ChainID{Uint256: id}
		if _, exists := out.Chains[chain]; exists {
			return Limits{}, errors.New("duplicate chain budget")
		}
		daily, e := positive(c.DailyBudgetWei)
		if e != nil {
			return Limits{}, fmt.Errorf("chain daily budget: %w", e)
		}
		sender, e := positive(c.SenderDailyWei)
		if e != nil {
			return Limits{}, fmt.Errorf("sender daily budget: %w", e)
		}
		if c.SenderDailyCount <= 0 {
			return Limits{}, errors.New("sender daily count must be positive")
		}
		out.Chains[chain] = ChainLimits{daily, sender, c.SenderDailyCount}
	}
	if _, err := parseIssuerProfiles(cfg.IssuanceProfiles, out.Chains); err != nil {
		return Limits{}, err
	}
	return out, nil
}

func parseIssuerProfiles(configs []IssuerProfileConfig, chains map[policy.ChainID]ChainLimits) (map[policy.ChainID]IssuerProfile, error) {
	profiles := make(map[policy.ChainID]IssuerProfile, len(configs))
	for _, c := range configs {
		id, err := positive(c.ChainID)
		if err != nil {
			return nil, fmt.Errorf("issuance chain ID: %w", err)
		}
		chain := policy.ChainID{Uint256: id}
		if _, ok := chains[chain]; !ok {
			return nil, errors.New("issuance profile has no accounting chain")
		}
		if _, exists := profiles[chain]; exists {
			return nil, errors.New("duplicate issuance profile")
		}
		paymaster, err := policy.ParseAddress(c.Paymaster)
		if err != nil || paymaster.IsZero() {
			return nil, errors.New("invalid issuance paymaster")
		}
		entry, err := policy.ParseAddress(c.EntryPoint)
		if err != nil || entry.IsZero() {
			return nil, errors.New("invalid issuance EntryPoint")
		}
		signer, err := policy.ParseAddress(c.ExpectedSigner)
		if err != nil || signer.IsZero() {
			return nil, errors.New("invalid expected signer")
		}
		var codeHash [32]byte
		if len(c.AccountCodeHash) != 66 || c.AccountCodeHash[:2] != "0x" {
			return nil, errors.New("invalid account code hash")
		}
		decoded, err := hex.DecodeString(c.AccountCodeHash[2:])
		if err != nil {
			return nil, errors.New("invalid account code hash")
		}
		copy(codeHash[:], decoded)
		if codeHash == [32]byte{} {
			return nil, errors.New("zero account code hash")
		}
		profiles[chain] = IssuerProfile{chain, paymaster, entry, codeHash, signer}
	}
	if len(profiles) != 0 && len(profiles) != len(chains) {
		return nil, errors.New("issuance profiles must cover all accounting chains")
	}
	return profiles, nil
}
func positive(raw string) (policy.Uint256, error) {
	v, e := policy.ParseUint256(raw)
	if e != nil || v.IsZero() {
		return policy.Uint256{}, errors.New("must be positive canonical uint256")
	}
	return v, nil
}

func ReadConfigJSON(data []byte) (Config, error) {
	if err := rejectDuplicateKeys(data); err != nil {
		return Config{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var c Config
	if err := dec.Decode(&c); err != nil {
		return Config{}, err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return Config{}, errors.New("trailing or malformed configuration data")
	}
	if _, err := NewLimits(c); err != nil {
		return Config{}, err
	}
	return c, nil
}

func rejectDuplicateKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	var walk func() error
	walk = func() error {
		token, err := dec.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]struct{}{}
			for dec.More() {
				k, e := dec.Token()
				if e != nil {
					return e
				}
				key, ok := k.(string)
				if !ok {
					return errors.New("invalid JSON object key")
				}
				if _, exists := seen[key]; exists {
					return fmt.Errorf("duplicate configuration key %q", key)
				}
				seen[key] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
		case '[':
			for dec.More() {
				if err := walk(); err != nil {
					return err
				}
			}
		default:
			return errors.New("invalid JSON delimiter")
		}
		_, err = dec.Token()
		return err
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing configuration data")
	}
	return nil
}

// RejectDuplicateKeys rejects ambiguous JSON objects before any request fields are interpreted.
func RejectDuplicateKeys(data []byte) error { return rejectDuplicateKeys(data) }

type Candidate struct {
	Scope, Key  string
	Fingerprint [32]byte
	Request     policy.Request
	Decision    policy.Decision
	PolicyJSON  []byte
	PolicyHash  [32]byte
	Limits      Limits
	Profile     *IssuerProfile
	Now         time.Time
}
type Repository interface {
	Admit(context.Context, Candidate) (Result, error)
}
type Observer interface {
	PolicyEvaluated(time.Duration)
	AdmissionCompleted(Result)
}

type Service struct {
	snapshot   policy.PolicySnapshot
	policyJSON []byte
	policyHash [32]byte
	limits     Limits
	profiles   map[policy.ChainID]IssuerProfile
	repo       Repository
	observer   Observer
}

func (s *Service) SetObserver(observer Observer) { s.observer = observer }

func NewService(policyJSON []byte, cfg Config, repo Repository) (*Service, error) {
	if repo == nil {
		return nil, errors.New("repository is required")
	}
	snapshot, err := policy.ReadSnapshotJSON(policyJSON)
	if err != nil {
		return nil, err
	}
	if uint64(snapshot.Version()) > uint64(^uint64(0)>>1) {
		return nil, errors.New("policy version exceeds database range")
	}
	limits, err := NewLimits(cfg)
	if err != nil {
		return nil, err
	}
	profiles, err := parseIssuerProfiles(cfg.IssuanceProfiles, limits.Chains)
	if err != nil {
		return nil, err
	}
	var staticConfig policy.Config
	if err := json.Unmarshal(policyJSON, &staticConfig); err != nil {
		return nil, err
	}
	if len(staticConfig.Chains) != len(limits.Chains) {
		return nil, errors.New("accounting chains must match static policy chains")
	}
	for _, chain := range staticConfig.Chains {
		v, _ := policy.ParseUint256(chain.ChainID)
		chainID := policy.ChainID{Uint256: v}
		if _, ok := limits.Chains[chainID]; !ok {
			return nil, errors.New("missing accounting limits for policy chain")
		}
		if profile, ok := profiles[chainID]; ok {
			entry, _ := policy.ParseAddress(chain.EntryPoint)
			if profile.EntryPoint != entry {
				return nil, errors.New("issuance EntryPoint differs from static policy")
			}
		}
	}
	staticConfig = canonicalStaticConfig(staticConfig)
	ordered := append([]ChainLimit(nil), cfg.Chains...)
	sort.Slice(ordered, func(i, j int) bool {
		a, _ := policy.ParseUint256(ordered[i].ChainID)
		b, _ := policy.ParseUint256(ordered[j].ChainID)
		return a.Cmp(b) < 0
	})
	cfg.Chains = ordered
	orderedProfiles := make([]IssuerProfileConfig, 0, len(profiles))
	for chain, profile := range profiles {
		orderedProfiles = append(orderedProfiles, IssuerProfileConfig{
			ChainID: chain.String(), Paymaster: profile.Paymaster.String(), EntryPoint: profile.EntryPoint.String(),
			AccountCodeHash: "0x" + hex.EncodeToString(profile.AccountCodeHash[:]), ExpectedSigner: profile.ExpectedSigner.String(),
		})
	}
	sort.Slice(orderedProfiles, func(i, j int) bool {
		a, _ := policy.ParseUint256(orderedProfiles[i].ChainID)
		b, _ := policy.ParseUint256(orderedProfiles[j].ChainID)
		return a.Cmp(b) < 0
	})
	cfg.IssuanceProfiles = orderedProfiles
	encoded, err := json.Marshal(struct {
		Static    any    `json:"static_policy"`
		Admission Config `json:"admission"`
	}{staticConfig, cfg})
	if err != nil {
		return nil, err
	}
	return &Service{snapshot: snapshot, policyJSON: encoded, policyHash: sha256.Sum256(encoded), limits: limits, profiles: profiles, repo: repo}, nil
}

func canonicalStaticConfig(cfg policy.Config) policy.Config {
	for i := range cfg.Chains {
		chain := &cfg.Chains[i]
		id, _ := policy.ParseUint256(chain.ChainID)
		chain.ChainID = id.String()
		entry, _ := policy.ParseAddress(chain.EntryPoint)
		chain.EntryPoint = entry.String()
		for j := range chain.Targets {
			target := &chain.Targets[j]
			address, _ := policy.ParseAddress(target.Address)
			target.Address = address.String()
			for k, raw := range target.Selectors {
				selector, _ := policy.ParseSelector(raw)
				target.Selectors[k] = selector.String()
			}
			sort.Strings(target.Selectors)
		}
		sort.Slice(chain.Targets, func(a, b int) bool { return chain.Targets[a].Address < chain.Targets[b].Address })
	}
	sort.Slice(cfg.Chains, func(i, j int) bool {
		a, _ := policy.ParseUint256(cfg.Chains[i].ChainID)
		b, _ := policy.ParseUint256(cfg.Chains[j].ChainID)
		return a.Cmp(b) < 0
	})
	for i, raw := range cfg.DeniedSenders {
		address, _ := policy.ParseAddress(raw)
		cfg.DeniedSenders[i] = address.String()
	}
	for i, raw := range cfg.DeniedTargets {
		address, _ := policy.ParseAddress(raw)
		cfg.DeniedTargets[i] = address.String()
	}
	sort.Strings(cfg.DeniedSenders)
	sort.Strings(cfg.DeniedTargets)
	return cfg
}

func (s *Service) Admit(ctx context.Context, scope, key string, input policy.RequestInput, now time.Time) (Result, error) {
	ctx, span := otel.Tracer("gasless/admission").Start(ctx, "admission.evaluate_and_reserve")
	defer span.End()
	if len(scope) < 1 || len(scope) > 128 || len(key) < 16 || len(key) > 128 || now.IsZero() {
		result := Result{Reason: InvalidRequest}
		if s.observer != nil {
			s.observer.AdmissionCompleted(result)
		}
		return result, nil
	}
	r, err := policy.Normalize(input)
	if err != nil {
		result := Result{Reason: StaticPolicyDenied, PolicyReason: policy.ReasonForNormalization(err), PolicyVersion: s.snapshot.Version()}
		if s.observer != nil {
			s.observer.AdmissionCompleted(result)
		}
		return result, nil
	}
	started := time.Now()
	_, policySpan := otel.Tracer("gasless/policy").Start(ctx, "policy.evaluate")
	decision := policy.Evaluate(r, s.snapshot, policy.EvaluationContext{Now: now})
	policySpan.End()
	if s.observer != nil {
		s.observer.PolicyEvaluated(time.Since(started))
	}
	c := Candidate{Scope: scope, Key: key, Fingerprint: Fingerprint(r), Request: r, Decision: decision, PolicyJSON: s.policyJSON, PolicyHash: s.policyHash, Limits: s.limits, Now: now.UTC()}
	if profile, ok := s.profiles[r.ChainID()]; ok {
		c.Profile = &profile
	}
	result, err := s.repo.Admit(ctx, c)
	if err != nil {
		reason := StorageUnavailable
		if errors.Is(err, ErrPolicyVersionConflict) {
			reason = PolicyVersionConflict
		}
		if s.observer != nil {
			s.observer.AdmissionCompleted(Result{Reason: reason})
		}
		return Result{Reason: reason}, err
	}
	if s.observer != nil {
		s.observer.AdmissionCompleted(result)
	}
	return result, nil
}

// Fingerprint commits every normalized field that can alter the account call or sponsor exposure.
// It is an off-chain idempotency identity, not a sponsorship signing digest.
func Fingerprint(r policy.Request) [32]byte {
	h := sha256.New()
	h.Write([]byte("gasless-request-v1\x00"))
	writeU := func(v policy.Uint256) { b := v.Bytes32(); h.Write(b[:]) }
	writeB := func(b []byte) {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(b)))
		h.Write(size[:])
		h.Write(b)
	}
	writeU(r.ChainID().Uint256)
	entry := r.EntryPoint()
	h.Write(entry[:])
	sender := r.Sender()
	h.Write(sender[:])
	writeU(r.Nonce().Uint256)
	writeB(r.OuterCallData())
	call := r.Call()
	h.Write(call.Target[:])
	writeU(call.Value.Uint256)
	h.Write(call.Selector[:])
	inner := sha256.Sum256(call.Data())
	h.Write(inner[:])
	for _, v := range []policy.Uint256{r.CallGasLimit().Uint256, r.VerificationGasLimit().Uint256, r.PreVerificationGas().Uint256, r.PaymasterVerificationGasLimit().Uint256, r.PaymasterPostOpGasLimit().Uint256, r.MaxFeePerGas().Uint256, r.MaxPriorityFeePerGas().Uint256} {
		writeU(v)
	}
	lifetime, provided := r.RequestedLifetime()
	if provided {
		h.Write([]byte{1})
	} else {
		h.Write([]byte{0})
	}
	var l [8]byte
	binary.BigEndian.PutUint64(l[:], lifetime)
	h.Write(l[:])
	return digest(h)
}
func digest(h hash.Hash) (out [32]byte) { copy(out[:], h.Sum(nil)); return }
