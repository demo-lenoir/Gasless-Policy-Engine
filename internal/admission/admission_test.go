package admission_test

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/demo-lenoir/gasless-policy-engine/internal/admission"
	"github.com/demo-lenoir/gasless-policy-engine/internal/policy"
)

type hashRepository struct{ hash [32]byte }

func (r *hashRepository) Admit(_ context.Context, c admission.Candidate) (admission.Result, error) {
	r.hash = c.PolicyHash
	return admission.Result{}, nil
}

func validInput() policy.RequestInput {
	inner := []byte{0x12, 0x34, 0x56, 0x78, 0xaa}
	b := make([]byte, 164)
	copy(b[:4], []byte{0xb6, 0x1d, 0x27, 0xf6})
	for i := 16; i < 36; i++ {
		b[i] = 0x11
	}
	b[99] = 96
	binary.BigEndian.PutUint64(b[124:132], uint64(len(inner)))
	copy(b[132:], inner)
	return policy.RequestInput{ChainID: "31337", EntryPoint: "0x433709009B8330FDa32311DF1C2AFA402eD8D009", Sender: "0x2222222222222222222222222222222222222222", Nonce: "7", CallData: "0x" + hex.EncodeToString(b), CallGasLimit: "100000", VerificationGasLimit: "100000", PreVerificationGas: "30000", PaymasterVerificationGasLimit: "80000", PaymasterPostOpGasLimit: "0", MaxFeePerGas: "10000000000", MaxPriorityFeePerGas: "1000000000"}
}
func normalize(t *testing.T, in policy.RequestInput) policy.Request {
	t.Helper()
	r, e := policy.Normalize(in)
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func TestFingerprintCanonicalAndFieldMutation(t *testing.T) {
	base := validInput()
	fingerprint := admission.Fingerprint(normalize(t, base))
	again := admission.Fingerprint(normalize(t, base))
	if fingerprint != again {
		t.Fatal("nondeterministic fingerprint")
	}
	upper := base
	upper.EntryPoint = strings.ToUpper(upper.EntryPoint[2:])
	upper.EntryPoint = "0x" + upper.EntryPoint
	upper.CallData = "0x" + strings.ToUpper(upper.CallData[2:])
	if admission.Fingerprint(normalize(t, upper)) != fingerprint {
		t.Fatal("hex casing changed fingerprint")
	}
	mutations := map[string]func(*policy.RequestInput){
		"chain": func(i *policy.RequestInput) { i.ChainID = "1" }, "entrypoint": func(i *policy.RequestInput) { i.EntryPoint = "0x1111111111111111111111111111111111111111" }, "sender": func(i *policy.RequestInput) { i.Sender = "0x3333333333333333333333333333333333333333" }, "nonce": func(i *policy.RequestInput) { i.Nonce = "8" },
		"target": func(i *policy.RequestInput) {
			b, _ := hex.DecodeString(i.CallData[2:])
			b[16] = 0x22
			i.CallData = "0x" + hex.EncodeToString(b)
		}, "selector": func(i *policy.RequestInput) {
			b, _ := hex.DecodeString(i.CallData[2:])
			b[132] = 0x99
			i.CallData = "0x" + hex.EncodeToString(b)
		}, "inner data": func(i *policy.RequestInput) {
			b, _ := hex.DecodeString(i.CallData[2:])
			b[136] = 0xbb
			i.CallData = "0x" + hex.EncodeToString(b)
		}, "value": func(i *policy.RequestInput) {
			b, _ := hex.DecodeString(i.CallData[2:])
			b[67] = 1
			i.CallData = "0x" + hex.EncodeToString(b)
		},
		"call gas": func(i *policy.RequestInput) { i.CallGasLimit = "100001" }, "verification gas": func(i *policy.RequestInput) { i.VerificationGasLimit = "100001" }, "preverification gas": func(i *policy.RequestInput) { i.PreVerificationGas = "30001" }, "paymaster verification gas": func(i *policy.RequestInput) { i.PaymasterVerificationGasLimit = "80001" }, "postop gas": func(i *policy.RequestInput) { i.PaymasterPostOpGasLimit = "1" }, "max fee": func(i *policy.RequestInput) { i.MaxFeePerGas = "10000000001" }, "priority fee": func(i *policy.RequestInput) { i.MaxPriorityFeePerGas = "1000000001" }, "lifetime": func(i *policy.RequestInput) { i.RequestedLifetimeSeconds = "30" },
	}
	for name, change := range mutations {
		t.Run(name, func(t *testing.T) {
			m := base
			change(&m)
			if admission.Fingerprint(normalize(t, m)) == fingerprint {
				t.Fatal("security field not committed")
			}
		})
	}
}
func TestLimitsRejectInvalidConfiguration(t *testing.T) {
	good := admission.Config{NativeAsset: "ETH", GlobalDailyBudgetWei: "100", Chains: []admission.ChainLimit{{ChainID: "31337", NativeAsset: "ETH", DailyBudgetWei: "50", SenderDailyWei: "10", SenderDailyCount: 1}}}
	if _, e := admission.NewLimits(good); e != nil {
		t.Fatal(e)
	}
	cases := map[string]func(*admission.Config){"zero global": func(c *admission.Config) { c.GlobalDailyBudgetWei = "0" }, "negative": func(c *admission.Config) { c.GlobalDailyBudgetWei = "-1" }, "overflow": func(c *admission.Config) { c.GlobalDailyBudgetWei = strings.Repeat("9", 79) }, "zero chain": func(c *admission.Config) { c.Chains[0].ChainID = "0" }, "zero count": func(c *admission.Config) { c.Chains[0].SenderDailyCount = 0 }, "asset mismatch": func(c *admission.Config) { c.Chains[0].NativeAsset = "OTHER" }, "duplicate chain": func(c *admission.Config) { c.Chains = append(c.Chains, c.Chains[0]) }}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			c := good
			c.Chains = append([]admission.ChainLimit(nil), good.Chains...)
			change(&c)
			if _, e := admission.NewLimits(c); e == nil {
				t.Fatal("accepted invalid limits")
			}
		})
	}
	data, e := os.ReadFile("../../config/admission.example.json")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = admission.ReadConfigJSON(data); e != nil {
		t.Fatal(e)
	}
	if _, e = admission.ReadConfigJSON(append(data, []byte(`{"trailing":true}`)...)); e == nil {
		t.Fatal("accepted trailing JSON")
	}
	duplicate := []byte(`{"native_asset":"ETH","native_asset":"ETH","global_daily_budget_wei":"1","chains":[]}`)
	if _, e = admission.ReadConfigJSON(duplicate); e == nil {
		t.Fatal("accepted duplicate JSON key")
	}
}
func TestReservationUpperBoundUsesPolicyDecision(t *testing.T) {
	data, e := os.ReadFile("../../config/policy.example.json")
	if e != nil {
		t.Fatal(e)
	}
	snap, e := policy.ReadSnapshotJSON(data)
	if e != nil {
		t.Fatal(e)
	}
	r := normalize(t, validInput())
	d := policy.Evaluate(r, snap, policy.EvaluationContext{Now: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)})
	if !d.Approved {
		t.Fatal(d.Reason)
	}
	if d.EstimatedUpperBound.String() != "3100000000000000" {
		t.Fatal(d.EstimatedUpperBound.String())
	}
}

func TestPublishedSnapshotHashIgnoresConfigurationOrder(t *testing.T) {
	raw, e := os.ReadFile("../../config/policy.example.json")
	if e != nil {
		t.Fatal(e)
	}
	var cfg policy.Config
	if e := json.Unmarshal(raw, &cfg); e != nil {
		t.Fatal(e)
	}
	cfg.Chains[0].Targets = append(cfg.Chains[0].Targets, policy.TargetConfig{Address: "0x4444444444444444444444444444444444444444", Selectors: []string{"0x87654321", "0xDEADBEEF"}})
	cfg.DeniedSenders = []string{"0x5555555555555555555555555555555555555555", "0x6666666666666666666666666666666666666666"}
	firstJSON, _ := json.Marshal(cfg)
	cfg.Chains[0].Targets[0], cfg.Chains[0].Targets[1] = cfg.Chains[0].Targets[1], cfg.Chains[0].Targets[0]
	cfg.Chains[0].Targets[0].Selectors[0], cfg.Chains[0].Targets[0].Selectors[1] = cfg.Chains[0].Targets[0].Selectors[1], cfg.Chains[0].Targets[0].Selectors[0]
	cfg.DeniedSenders[0], cfg.DeniedSenders[1] = cfg.DeniedSenders[1], cfg.DeniedSenders[0]
	secondJSON, _ := json.Marshal(cfg)
	limits := admission.Config{NativeAsset: "ETH", GlobalDailyBudgetWei: "1000000000000000000", Chains: []admission.ChainLimit{{ChainID: "31337", NativeAsset: "ETH", DailyBudgetWei: "500000000000000000", SenderDailyWei: "100000000000000000", SenderDailyCount: 20}}}
	a, b := &hashRepository{}, &hashRepository{}
	sa, e := admission.NewService(firstJSON, limits, a)
	if e != nil {
		t.Fatal(e)
	}
	sb, e := admission.NewService(secondJSON, limits, b)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	_, _ = sa.Admit(context.Background(), "client-a", "request-key-00000001", validInput(), now)
	_, _ = sb.Admit(context.Background(), "client-a", "request-key-00000001", validInput(), now)
	if a.hash != b.hash {
		t.Fatal("equivalent snapshots have different published hashes")
	}
}

func TestIssuerProfileValidationAndSnapshotIdentity(t *testing.T) {
	policyJSON, err := os.ReadFile("../../config/policy.example.json")
	if err != nil {
		t.Fatal(err)
	}
	base := admission.Config{
		NativeAsset: "ETH", GlobalDailyBudgetWei: "1000000000000000000",
		Chains: []admission.ChainLimit{{ChainID: "31337", NativeAsset: "ETH", DailyBudgetWei: "500000000000000000", SenderDailyWei: "100000000000000000", SenderDailyCount: 20}},
		IssuanceProfiles: []admission.IssuerProfileConfig{{
			ChainID: "31337", Paymaster: "0x3333333333333333333333333333333333333333",
			EntryPoint:      validInput().EntryPoint,
			AccountCodeHash: "0x0000000000000000000000000000000000000000000000000000000000000003",
			ExpectedSigner:  "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf",
		}},
	}
	invalid := map[string]func(*admission.Config){
		"duplicate":     func(c *admission.Config) { c.IssuanceProfiles = append(c.IssuanceProfiles, c.IssuanceProfiles[0]) },
		"unknown chain": func(c *admission.Config) { c.IssuanceProfiles[0].ChainID = "1" },
		"zero paymaster": func(c *admission.Config) {
			c.IssuanceProfiles[0].Paymaster = "0x0000000000000000000000000000000000000000"
		},
		"short hash":     func(c *admission.Config) { c.IssuanceProfiles[0].AccountCodeHash = "0x03" },
		"zero hash":      func(c *admission.Config) { c.IssuanceProfiles[0].AccountCodeHash = "0x" + strings.Repeat("0", 64) },
		"invalid signer": func(c *admission.Config) { c.IssuanceProfiles[0].ExpectedSigner = "bad" },
		"wrong entrypoint": func(c *admission.Config) {
			c.IssuanceProfiles[0].EntryPoint = "0x1111111111111111111111111111111111111111"
		},
	}
	for name, mutate := range invalid {
		t.Run(name, func(t *testing.T) {
			cfg := base
			cfg.IssuanceProfiles = append([]admission.IssuerProfileConfig(nil), base.IssuanceProfiles...)
			mutate(&cfg)
			if _, err := admission.NewService(policyJSON, cfg, &hashRepository{}); err == nil {
				t.Fatal("invalid issuance profile accepted")
			}
		})
	}
	read := func(cfg admission.Config) [32]byte {
		t.Helper()
		repo := &hashRepository{}
		svc, err := admission.NewService(policyJSON, cfg, repo)
		if err != nil {
			t.Fatal(err)
		}
		_, err = svc.Admit(context.Background(), "client-a", "request-key-00000001", validInput(), time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
		if err != nil {
			t.Fatal(err)
		}
		return repo.hash
	}
	original := read(base)
	changed := base
	changed.IssuanceProfiles = append([]admission.IssuerProfileConfig(nil), base.IssuanceProfiles...)
	changed.IssuanceProfiles[0].Paymaster = "0x4444444444444444444444444444444444444444"
	if original == read(changed) {
		t.Fatal("changed issuance profile retained policy hash")
	}
	upper := base
	upper.IssuanceProfiles = append([]admission.IssuerProfileConfig(nil), base.IssuanceProfiles...)
	upper.IssuanceProfiles[0].Paymaster = "0x" + strings.ToUpper(upper.IssuanceProfiles[0].Paymaster[2:])
	if original != read(upper) {
		t.Fatal("equivalent address changed policy hash")
	}
}
