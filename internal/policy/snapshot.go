package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const absoluteMaxLifetimeSeconds uint64 = 300

type TargetConfig struct {
	Address   string   `json:"address"`
	Selectors []string `json:"selectors"`
}

type ChainConfig struct {
	ChainID    string         `json:"chain_id"`
	EntryPoint string         `json:"entry_point"`
	Targets    []TargetConfig `json:"targets"`
}

type Config struct {
	Version                     PolicyVersion `json:"version"`
	Enabled                     bool          `json:"enabled"`
	Chains                      []ChainConfig `json:"chains"`
	DeniedSenders               []string      `json:"denied_senders"`
	DeniedTargets               []string      `json:"denied_targets"`
	MaxCallValueWei             string        `json:"max_call_value_wei"`
	MaxCallGas                  string        `json:"max_call_gas"`
	MaxVerificationGas          string        `json:"max_verification_gas"`
	MaxPreVerificationGas       string        `json:"max_pre_verification_gas"`
	MaxPaymasterVerificationGas string        `json:"max_paymaster_verification_gas"`
	MaxPaymasterPostOpGas       string        `json:"max_paymaster_post_op_gas"`
	MaxFeePerGasWei             string        `json:"max_fee_per_gas_wei"`
	MaxPriorityFeePerGasWei     string        `json:"max_priority_fee_per_gas_wei"`
	MaxEstimatedCostWei         string        `json:"max_estimated_cost_wei"`
	MinLifetimeSeconds          uint64        `json:"min_lifetime_seconds"`
	DefaultLifetimeSeconds      uint64        `json:"default_lifetime_seconds"`
	MaxLifetimeSeconds          uint64        `json:"max_lifetime_seconds"`
}

type chainRules struct {
	entryPoint Address
	targets    map[Address]map[Selector]struct{}
}

// PolicySnapshot owns its maps. No caller-owned configuration slice is retained.
type PolicySnapshot struct {
	version                     PolicyVersion
	enabled                     bool
	chains                      map[ChainID]chainRules
	deniedSenders               map[Address]struct{}
	deniedTargets               map[Address]struct{}
	maxCallValue                Wei
	maxCallGas                  Gas
	maxVerificationGas          Gas
	maxPreVerificationGas       Gas
	maxPaymasterVerificationGas Gas
	maxPaymasterPostOpGas       Gas
	maxFee                      Fee
	maxPriorityFee              Fee
	maxEstimatedCost            Wei
	minLifetimeSeconds          uint64
	defaultLifetimeSeconds      uint64
	maxLifetimeSeconds          uint64
	valid                       bool
}

func (s PolicySnapshot) Version() PolicyVersion { return s.version }
func (s PolicySnapshot) Enabled() bool          { return s.enabled }

func ReadSnapshotJSON(data []byte) (PolicySnapshot, error) {
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return PolicySnapshot{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var cfg Config
	if err := decoder.Decode(&cfg); err != nil {
		return PolicySnapshot{}, err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return PolicySnapshot{}, errors.New("trailing policy JSON")
	}
	return NewSnapshot(cfg)
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("non-string JSON object key")
				}
				if _, exists := seen[key]; exists {
					return fmt.Errorf("duplicate JSON key %q", key)
				}
				seen[key] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
		default:
			return errors.New("unexpected JSON delimiter")
		}
		_, err = decoder.Token()
		return err
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing policy JSON")
	}
	return nil
}

func NewSnapshot(cfg Config) (PolicySnapshot, error) {
	var s PolicySnapshot
	if cfg.Version == 0 {
		return s, errors.New("policy version must be positive")
	}
	if len(cfg.Chains) == 0 {
		return s, errors.New("policy must define at least one chain")
	}
	s.version = cfg.Version
	s.enabled = cfg.Enabled
	s.chains = make(map[ChainID]chainRules, len(cfg.Chains))
	for _, entry := range cfg.Chains {
		id, err := ParseUint256(entry.ChainID)
		if err != nil || id.IsZero() {
			return PolicySnapshot{}, errors.New("invalid allowed chain ID")
		}
		chain := ChainID{id}
		if _, exists := s.chains[chain]; exists {
			return PolicySnapshot{}, errors.New("duplicate allowed chain")
		}
		point, err := ParseAddress(entry.EntryPoint)
		if err != nil || point.IsZero() {
			return PolicySnapshot{}, errors.New("invalid EntryPoint address")
		}
		if len(entry.Targets) == 0 {
			return PolicySnapshot{}, errors.New("allowed chain has no targets")
		}
		rules := chainRules{entryPoint: point, targets: make(map[Address]map[Selector]struct{}, len(entry.Targets))}
		for _, target := range entry.Targets {
			address, parseErr := ParseAddress(target.Address)
			if parseErr != nil || address.IsZero() {
				return PolicySnapshot{}, errors.New("invalid target address")
			}
			if _, exists := rules.targets[address]; exists {
				return PolicySnapshot{}, errors.New("duplicate target rule")
			}
			if len(target.Selectors) == 0 {
				return PolicySnapshot{}, errors.New("target has no allowed selectors")
			}
			selectors := make(map[Selector]struct{}, len(target.Selectors))
			for _, raw := range target.Selectors {
				selector, parseErr := ParseSelector(raw)
				if parseErr != nil {
					return PolicySnapshot{}, fmt.Errorf("invalid selector for %s: %w", address, parseErr)
				}
				selectors[selector] = struct{}{}
			}
			rules.targets[address] = selectors
		}
		s.chains[chain] = rules
	}
	s.deniedSenders = make(map[Address]struct{}, len(cfg.DeniedSenders))
	for _, raw := range cfg.DeniedSenders {
		address, err := ParseAddress(raw)
		if err != nil || address.IsZero() {
			return PolicySnapshot{}, errors.New("invalid denied sender")
		}
		s.deniedSenders[address] = struct{}{}
	}
	s.deniedTargets = make(map[Address]struct{}, len(cfg.DeniedTargets))
	for _, raw := range cfg.DeniedTargets {
		address, err := ParseAddress(raw)
		if err != nil || address.IsZero() {
			return PolicySnapshot{}, errors.New("invalid denied target")
		}
		s.deniedTargets[address] = struct{}{}
	}
	var err error
	if s.maxCallValue, err = parseWeiCap(cfg.MaxCallValueWei, false); err != nil {
		return PolicySnapshot{}, fmt.Errorf("max call value: %w", err)
	}
	if s.maxEstimatedCost, err = parseWeiCap(cfg.MaxEstimatedCostWei, true); err != nil {
		return PolicySnapshot{}, fmt.Errorf("max estimated cost: %w", err)
	}
	minimumCost, _ := ParseUint256("4")
	if s.maxEstimatedCost.Cmp(minimumCost) < 0 {
		return PolicySnapshot{}, errors.New("estimated cost cap cannot admit any v1 operation")
	}
	gasCaps := []struct {
		name      string
		raw       string
		allowZero bool
		set       func(Gas)
	}{
		{"call gas", cfg.MaxCallGas, false, func(v Gas) { s.maxCallGas = v }},
		{"verification gas", cfg.MaxVerificationGas, false, func(v Gas) { s.maxVerificationGas = v }},
		{"pre-verification gas", cfg.MaxPreVerificationGas, false, func(v Gas) { s.maxPreVerificationGas = v }},
		{"paymaster verification gas", cfg.MaxPaymasterVerificationGas, false, func(v Gas) { s.maxPaymasterVerificationGas = v }},
		{"paymaster post-operation gas", cfg.MaxPaymasterPostOpGas, true, func(v Gas) { s.maxPaymasterPostOpGas = v }},
	}
	for _, cap := range gasCaps {
		v, parseErr := ParseUint256(cap.raw)
		if parseErr != nil || !v.withinEntryPointGasRange() || (!cap.allowZero && v.IsZero()) {
			return PolicySnapshot{}, fmt.Errorf("invalid maximum %s", cap.name)
		}
		cap.set(Gas{v})
	}
	if !s.maxPaymasterPostOpGas.IsZero() {
		return PolicySnapshot{}, errors.New("v1 paymaster post-operation gas must be zero")
	}
	feeCaps := []struct {
		name string
		raw  string
		set  func(Fee)
	}{
		{"max fee", cfg.MaxFeePerGasWei, func(v Fee) { s.maxFee = v }},
		{"max priority fee", cfg.MaxPriorityFeePerGasWei, func(v Fee) { s.maxPriorityFee = v }},
	}
	for _, cap := range feeCaps {
		v, parseErr := ParseUint256(cap.raw)
		if parseErr != nil || !v.withinEntryPointGasRange() || v.IsZero() {
			return PolicySnapshot{}, fmt.Errorf("invalid %s", cap.name)
		}
		cap.set(Fee{v})
	}
	if s.maxPriorityFee.Cmp(s.maxFee.Uint256) > 0 {
		return PolicySnapshot{}, errors.New("priority fee cap exceeds max fee cap")
	}
	if cfg.MinLifetimeSeconds == 0 || cfg.MinLifetimeSeconds > cfg.DefaultLifetimeSeconds || cfg.DefaultLifetimeSeconds > cfg.MaxLifetimeSeconds || cfg.MaxLifetimeSeconds > absoluteMaxLifetimeSeconds {
		return PolicySnapshot{}, errors.New("invalid sponsorship lifetime bounds")
	}
	s.minLifetimeSeconds = cfg.MinLifetimeSeconds
	s.defaultLifetimeSeconds = cfg.DefaultLifetimeSeconds
	s.maxLifetimeSeconds = cfg.MaxLifetimeSeconds
	s.valid = true
	return s, nil
}

func parseWeiCap(raw string, positive bool) (Wei, error) {
	v, err := ParseUint256(raw)
	if err != nil || (positive && v.IsZero()) {
		return Wei{}, errors.New("invalid wei cap")
	}
	return Wei{v}, nil
}
