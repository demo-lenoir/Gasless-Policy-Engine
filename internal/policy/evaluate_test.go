package policy

import (
	"encoding/hex"
	"math/big"
	"reflect"
	"testing"
	"time"
)

func setCall(t *testing.T, input *RequestInput, change func(*Call)) {
	t.Helper()
	raw, err := hex.DecodeString(input.CallData[2:])
	if err != nil {
		t.Fatal(err)
	}
	call, err := DecodeExecute(raw)
	if err != nil {
		t.Fatal(err)
	}
	change(&call)
	input.CallData = "0x" + hex.EncodeToString(encodeExecute(call))
}

func TestEvaluateAllowedAndEstimatedUpperBound(t *testing.T) {
	s := testSnapshot(t)
	r, err := Normalize(testInput(t))
	if err != nil {
		t.Fatal(err)
	}
	d := Evaluate(r, s, testContext())
	if !d.Approved || d.Reason != ReasonApproved || d.PolicyVersion != 1 {
		t.Fatalf("unexpected decision %+v", d)
	}
	if d.EstimatedUpperBound.String() != "3100000000000000" {
		t.Fatalf("upper bound %s", d.EstimatedUpperBound)
	}
	if d.ValidUntil.Sub(d.ValidAfter) != 60*time.Second {
		t.Fatal("default lifetime differs")
	}
	if d.NormalizedRequest().Call().Target.String() != testTarget {
		t.Fatal("decision lost derived target")
	}
	copyOfRequest := d.NormalizedRequest()
	outer := copyOfRequest.OuterCallData()
	outer[0] = 0
	if d.NormalizedRequest().OuterCallData()[0] != 0xb6 {
		t.Fatal("decision exposed mutable request")
	}
	if !reflect.DeepEqual(d, Evaluate(r, s, testContext())) {
		t.Fatal("same inputs changed decision")
	}
}

func TestEvaluateStaticRulePrecedence(t *testing.T) {
	base := testInput(t)
	cases := []struct {
		name      string
		configure func(*Config)
		change    func(*RequestInput)
		want      Reason
	}{
		{"disabled before malformed", func(c *Config) { c.Enabled = false }, func(r *RequestInput) { r.ChainID = "bad" }, ReasonEmergencyDisabled},
		{"malformed before chain", nil, func(r *RequestInput) { r.ChainID = "01" }, ReasonMalformedRequest},
		{"unsupported shape", nil, func(r *RequestInput) { r.CallData = "0x1234" }, ReasonUnsupportedCallShape},
		{"chain before sender", func(c *Config) { c.DeniedSenders = []string{testDeniedSender} }, func(r *RequestInput) { r.ChainID = "1"; r.Sender = testDeniedSender }, ReasonChainNotAllowed},
		{"EntryPoint before sender", func(c *Config) { c.DeniedSenders = []string{testDeniedSender} }, func(r *RequestInput) { r.EntryPoint = testOtherTarget; r.Sender = testDeniedSender }, ReasonEntryPointNotAllowed},
		{"sender before selector", func(c *Config) { c.DeniedSenders = []string{testDeniedSender} }, func(r *RequestInput) { r.Sender = testDeniedSender; setCall(t, r, func(c *Call) { c.data[0] = 0xff }) }, ReasonSenderDenylisted},
		{"target deny before allow", func(c *Config) { c.DeniedTargets = []string{testTarget} }, func(r *RequestInput) { setCall(t, r, func(c *Call) { c.data[0] = 0xff }) }, ReasonTargetDenylisted},
		{"wrong target", nil, func(r *RequestInput) { setCall(t, r, func(c *Call) { c.Target, _ = ParseAddress(testOtherTarget) }) }, ReasonTargetNotAllowed},
		{"wrong selector", nil, func(r *RequestInput) { setCall(t, r, func(c *Call) { c.data[0] = 0xff }) }, ReasonSelectorNotAllowed},
		{"wrong target with allowed selector", nil, func(r *RequestInput) { setCall(t, r, func(c *Call) { c.Target, _ = ParseAddress(testOtherTarget) }) }, ReasonTargetNotAllowed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig(t)
			if tc.configure != nil {
				tc.configure(&cfg)
			}
			s, err := NewSnapshot(cfg)
			if err != nil {
				t.Fatal(err)
			}
			input := base
			tc.change(&input)
			d := EvaluateRaw(input, s, testContext())
			if d.Approved || d.Reason != tc.want {
				t.Fatalf("got approved=%v reason=%s want=%s", d.Approved, d.Reason, tc.want)
			}
		})
	}
}

func TestSelectorIsScopedToTargetAndChain(t *testing.T) {
	cfg := testConfig(t)
	cfg.Chains[0].Targets = append(cfg.Chains[0].Targets, TargetConfig{Address: testOtherTarget, Selectors: []string{"0x87654321"}})
	cfg.Chains = append(cfg.Chains, ChainConfig{ChainID: "1", EntryPoint: testEntryPoint, Targets: []TargetConfig{{Address: testTarget, Selectors: []string{"0x87654321"}}}})
	s, err := NewSnapshot(cfg)
	if err != nil {
		t.Fatal(err)
	}
	input := testInput(t)
	if !EvaluateRaw(input, s, testContext()).Approved {
		t.Fatal("allowed target and selector denied")
	}
	setCall(t, &input, func(c *Call) { c.Target, _ = ParseAddress(testOtherTarget) })
	if got := EvaluateRaw(input, s, testContext()).Reason; got != ReasonSelectorNotAllowed {
		t.Fatalf("other target inherited selector: %s", got)
	}
	input = testInput(t)
	input.ChainID = "1"
	if got := EvaluateRaw(input, s, testContext()).Reason; got != ReasonSelectorNotAllowed {
		t.Fatalf("other chain inherited selector: %s", got)
	}
}

func TestNumericBoundaries(t *testing.T) {
	s := testSnapshot(t)
	fields := []struct {
		name   string
		max    string
		set    func(*RequestInput, string)
		denied Reason
	}{
		{"call value", "1000000000000000", func(r *RequestInput, v string) {
			setCall(t, r, func(c *Call) { n, _ := ParseUint256(v); c.Value = Wei{n} })
		}, ReasonCallValueExceeded},
		{"call gas", "500000", func(r *RequestInput, v string) { r.CallGasLimit = v }, ReasonCallGasLimitExceeded},
		{"verification gas", "500000", func(r *RequestInput, v string) { r.VerificationGasLimit = v }, ReasonVerificationGasLimitExceeded},
		{"pre-verification gas", "100000", func(r *RequestInput, v string) { r.PreVerificationGas = v }, ReasonPreVerificationGasLimitExceeded},
		{"paymaster verification gas", "200000", func(r *RequestInput, v string) { r.PaymasterVerificationGasLimit = v }, ReasonPaymasterVerificationGasExceeded},
		{"max fee", "100000000000", func(r *RequestInput, v string) { r.MaxFeePerGas = v }, ReasonMaxFeeExceeded},
		{"priority fee", "2000000000", func(r *RequestInput, v string) { r.MaxPriorityFeePerGas = v }, ReasonPriorityFeeExceeded},
	}
	for _, field := range fields {
		max, _ := new(big.Int).SetString(field.max, 10)
		for _, delta := range []int64{-1, 0, 1} {
			name := field.name + " delta=" + big.NewInt(delta).String()
			t.Run(name, func(t *testing.T) {
				input := testInput(t)
				value := new(big.Int).Add(max, big.NewInt(delta)).String()
				field.set(&input, value)
				d := EvaluateRaw(input, s, testContext())
				if delta <= 0 && !d.Approved {
					t.Fatalf("boundary %s denied: %s", value, d.Reason)
				}
				if delta > 0 && (d.Approved || d.Reason != field.denied) {
					t.Fatalf("boundary %s returned %s", value, d.Reason)
				}
			})
		}
	}
	postOp := testInput(t)
	postOp.PaymasterPostOpGasLimit = "1"
	if got := EvaluateRaw(postOp, s, testContext()).Reason; got != ReasonPaymasterPostOpGasExceeded {
		t.Fatalf("postOp gas unbounded: %s", got)
	}
	if !EvaluateRaw(testInput(t), s, testContext()).Approved {
		t.Fatal("zero postOp gas denied")
	}
}

func TestEstimatedCostAndValidityBounds(t *testing.T) {
	base := testInput(t)
	r, err := Normalize(base)
	if err != nil {
		t.Fatal(err)
	}
	upper, ok := EstimatedUpperBound(r)
	if !ok || upper.String() != "3100000000000000" {
		t.Fatalf("upper bound: %s %v", upper, ok)
	}
	for _, delta := range []int64{-1, 0, 1} {
		cfg := testConfig(t)
		cap := new(big.Int).Add(upper.Big(), big.NewInt(delta))
		cfg.MaxEstimatedCostWei = cap.String()
		s, err := NewSnapshot(cfg)
		if err != nil {
			t.Fatal(err)
		}
		d := EvaluateRaw(base, s, testContext())
		if delta < 0 && d.Reason != ReasonEstimatedCostExceeded {
			t.Fatalf("cost over cap was %s", d.Reason)
		}
		if delta >= 0 && !d.Approved {
			t.Fatalf("cost at/below cap denied: %s", d.Reason)
		}
	}
	s := testSnapshot(t)
	for _, tc := range []struct {
		lifetime string
		approved bool
	}{
		{"9", false}, {"10", true}, {"11", true}, {"119", true}, {"120", true}, {"121", false}, {"0", false},
	} {
		input := base
		input.RequestedLifetimeSeconds = tc.lifetime
		d := EvaluateRaw(input, s, testContext())
		if d.Approved != tc.approved {
			t.Fatalf("lifetime %s: %s", tc.lifetime, d.Reason)
		}
		if !tc.approved && d.Reason != ReasonInvalidValidity {
			t.Fatalf("lifetime %s wrong reason %s", tc.lifetime, d.Reason)
		}
	}
	if got := EvaluateRaw(base, s, EvaluationContext{}).Reason; got != ReasonInvalidValidity {
		t.Fatalf("zero evaluation time: %s", got)
	}
	feeInversion := base
	feeInversion.MaxFeePerGas = "1"
	if got := EvaluateRaw(feeInversion, s, testContext()).Reason; got != ReasonPriorityFeeExceeded {
		t.Fatalf("priority fee above max fee: %s", got)
	}
	nearFlag := EvaluationContext{Now: time.Unix(1<<47-59, 0)}
	if got := EvaluateRaw(base, s, nearFlag).Reason; got != ReasonInvalidValidity {
		t.Fatalf("block validity flag overflow: %s", got)
	}
}

func TestSecurityFieldMutations(t *testing.T) {
	cfg := testConfig(t)
	cfg.DeniedSenders = []string{testDeniedSender}
	s, err := NewSnapshot(cfg)
	if err != nil {
		t.Fatal(err)
	}
	base := testInput(t)
	if !EvaluateRaw(base, s, testContext()).Approved {
		t.Fatal("baseline denied")
	}
	mutations := []struct {
		name   string
		change func(*RequestInput)
	}{
		{"chain", func(r *RequestInput) { r.ChainID = "1" }},
		{"EntryPoint", func(r *RequestInput) { r.EntryPoint = testOtherTarget }},
		{"sender", func(r *RequestInput) { r.Sender = testDeniedSender }},
		{"target", func(r *RequestInput) { setCall(t, r, func(c *Call) { c.Target, _ = ParseAddress(testOtherTarget) }) }},
		{"selector", func(r *RequestInput) { setCall(t, r, func(c *Call) { c.data[0] = 0xff }) }},
		{"calldata", func(r *RequestInput) { setCall(t, r, func(c *Call) { c.data[0] = 0xff; c.data[4] ^= 1 }) }},
		{"value", func(r *RequestInput) {
			setCall(t, r, func(c *Call) { n, _ := ParseUint256("1000000000000001"); c.Value = Wei{n} })
		}},
		{"call gas", func(r *RequestInput) { r.CallGasLimit = "500001" }},
		{"verification gas", func(r *RequestInput) { r.VerificationGasLimit = "500001" }},
		{"preverification gas", func(r *RequestInput) { r.PreVerificationGas = "100001" }},
		{"paymaster verification gas", func(r *RequestInput) { r.PaymasterVerificationGasLimit = "200001" }},
		{"postop gas", func(r *RequestInput) { r.PaymasterPostOpGasLimit = "1" }},
		{"max fee", func(r *RequestInput) { r.MaxFeePerGas = "100000000001" }},
		{"priority fee", func(r *RequestInput) { r.MaxPriorityFeePerGas = "2000000001" }},
		{"validity", func(r *RequestInput) { r.RequestedLifetimeSeconds = "121" }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			input := base
			mutation.change(&input)
			if d := EvaluateRaw(input, s, testContext()); d.Approved {
				t.Fatalf("mutation %s remained approved", mutation.name)
			}
		})
	}
	argumentMutation := base
	setCall(t, &argumentMutation, func(c *Call) { c.data[4] ^= 1 })
	before, _ := Normalize(base)
	after, _ := Normalize(argumentMutation)
	if reflect.DeepEqual(before.Call().Data(), after.Call().Data()) {
		t.Fatal("argument change vanished in normalized subject")
	}
	if !Evaluate(after, s, testContext()).Approved {
		t.Fatal("allowed selector with different argument denied")
	}
	nonceMutation := base
	nonceMutation.Nonce = "8"
	changedNonce, err := Normalize(nonceMutation)
	if err != nil || changedNonce.Nonce() == before.Nonce() {
		t.Fatal("nonce mutation vanished in normalized request")
	}
}
