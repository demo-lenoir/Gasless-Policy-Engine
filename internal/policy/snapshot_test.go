package policy

import (
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestExamplePolicyLoads(t *testing.T) {
	s := testSnapshot(t)
	if s.Version() != 1 || !s.Enabled() {
		t.Fatal("example policy not enabled at version one")
	}
}

func TestSnapshotRejectsInvalidConfiguration(t *testing.T) {
	cases := []struct {
		name   string
		change func(*Config)
	}{
		{"empty version", func(c *Config) { c.Version = 0 }},
		{"no chains", func(c *Config) { c.Chains = nil }},
		{"zero chain", func(c *Config) { c.Chains[0].ChainID = "0" }},
		{"wildcard chain", func(c *Config) { c.Chains[0].ChainID = "*" }},
		{"duplicate chain", func(c *Config) { c.Chains = append(c.Chains, c.Chains[0]) }},
		{"invalid EntryPoint", func(c *Config) { c.Chains[0].EntryPoint = "0x1" }},
		{"no targets", func(c *Config) { c.Chains[0].Targets = nil }},
		{"zero target", func(c *Config) { c.Chains[0].Targets[0].Address = "0x0000000000000000000000000000000000000000" }},
		{"duplicate target", func(c *Config) { c.Chains[0].Targets = append(c.Chains[0].Targets, c.Chains[0].Targets[0]) }},
		{"no selectors", func(c *Config) { c.Chains[0].Targets[0].Selectors = nil }},
		{"invalid selector", func(c *Config) { c.Chains[0].Targets[0].Selectors[0] = "0x123" }},
		{"wildcard selector", func(c *Config) { c.Chains[0].Targets[0].Selectors[0] = "*" }},
		{"bad denied sender", func(c *Config) { c.DeniedSenders = []string{"bad"} }},
		{"bad denied target", func(c *Config) { c.DeniedTargets = []string{"bad"} }},
		{"negative value cap", func(c *Config) { c.MaxCallValueWei = "-1" }},
		{"zero call gas cap", func(c *Config) { c.MaxCallGas = "0" }},
		{"postop gas cap", func(c *Config) { c.MaxPaymasterPostOpGas = "1" }},
		{"fee cap over v09 range", func(c *Config) { c.MaxFeePerGasWei = maxEntryPointGasValue.String() + "0" }},
		{"priority above fee", func(c *Config) { c.MaxPriorityFeePerGasWei = "100000000001" }},
		{"zero cost cap", func(c *Config) { c.MaxEstimatedCostWei = "0" }},
		{"impossible cost cap", func(c *Config) { c.MaxEstimatedCostWei = "3" }},
		{"zero lifetime", func(c *Config) { c.MinLifetimeSeconds = 0 }},
		{"default outside range", func(c *Config) { c.DefaultLifetimeSeconds = 121 }},
		{"lifetime too long", func(c *Config) { c.MaxLifetimeSeconds = 301 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := testConfig(t)
			tc.change(&c)
			if _, err := NewSnapshot(c); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
}

func TestSnapshotJSONRejectsUnknownDuplicateAndTrailing(t *testing.T) {
	data, err := os.ReadFile("../../config/policy.example.json")
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string]string{
		"unknown":   strings.Replace(string(data), `"version": 1`, `"version": 1, "unknown": true`, 1),
		"duplicate": strings.Replace(string(data), `"version": 1`, `"version": 1, "version": 2`, 1),
		"trailing":  string(data) + "{}",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ReadSnapshotJSON([]byte(raw)); err == nil {
				t.Fatal("invalid JSON policy accepted")
			}
		})
	}
}

func TestSnapshotOrderingAndInputMutationDoNotChangeDecision(t *testing.T) {
	cfg := testConfig(t)
	cfg.Chains[0].Targets = append(cfg.Chains[0].Targets, TargetConfig{Address: testOtherTarget, Selectors: []string{"0x87654321", "0x12345678"}})
	cfg.Chains = append(cfg.Chains, ChainConfig{ChainID: "1", EntryPoint: testEntryPoint, Targets: []TargetConfig{{Address: testTarget, Selectors: []string{"0x12345678"}}}})
	cfg.DeniedSenders = []string{testDeniedSender, testOtherTarget, testDeniedSender}
	cfg.DeniedTargets = []string{testOtherTarget, testOtherTarget}
	a, err := NewSnapshot(cfg)
	if err != nil {
		t.Fatal(err)
	}
	slices.Reverse(cfg.Chains)
	slices.Reverse(cfg.Chains[1].Targets)
	slices.Reverse(cfg.Chains[1].Targets[0].Selectors)
	slices.Reverse(cfg.DeniedSenders)
	slices.Reverse(cfg.DeniedTargets)
	b, err := NewSnapshot(cfg)
	if err != nil {
		t.Fatal(err)
	}
	inputs := []RequestInput{testInput(t)}
	other := testInput(t)
	other.ChainID = "1"
	inputs = append(inputs, other)
	other = testInput(t)
	other.Sender = testDeniedSender
	inputs = append(inputs, other)
	other = testInput(t)
	setCall(t, &other, func(c *Call) {
		c.Target, _ = ParseAddress(testOtherTarget)
		c.data = []byte{0x87, 0x65, 0x43, 0x21, 0xaa}
	})
	inputs = append(inputs, other)
	for _, input := range inputs {
		if !reflect.DeepEqual(EvaluateRaw(input, a, testContext()), EvaluateRaw(input, b, testContext())) {
			t.Fatal("order changed decision")
		}
	}
	// Mutating the config after construction cannot alter a snapshot.
	cfg.Chains[1].Targets[0].Selectors[0] = "0xffffffff"
	cfg.DeniedSenders[0] = testSender
	if !EvaluateRaw(testInput(t), a, testContext()).Approved {
		t.Fatal("snapshot retained caller slices")
	}
}
