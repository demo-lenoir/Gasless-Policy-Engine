package policy

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

type RequestInput struct {
	ChainID                       string `json:"chain_id"`
	EntryPoint                    string `json:"entry_point"`
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
	RequestedLifetimeSeconds      string `json:"requested_lifetime_seconds,omitempty"`
}

type Request struct {
	chainID                  ChainID
	entryPoint               Address
	sender                   Address
	nonce                    Nonce
	outerCallData            []byte
	call                     Call
	callGas                  Gas
	verificationGas          Gas
	preVerificationGas       Gas
	paymasterVerificationGas Gas
	paymasterPostOpGas       Gas
	maxFee                   Fee
	maxPriorityFee           Fee
	requestedLifetimeSeconds uint64
	lifetimeProvided         bool
	valid                    bool
}

func (r Request) ChainID() ChainID                   { return r.chainID }
func (r Request) EntryPoint() Address                { return r.entryPoint }
func (r Request) Sender() Address                    { return r.sender }
func (r Request) Nonce() Nonce                       { return r.nonce }
func (r Request) OuterCallData() []byte              { return bytes.Clone(r.outerCallData) }
func (r Request) CallGasLimit() Gas                  { return r.callGas }
func (r Request) VerificationGasLimit() Gas          { return r.verificationGas }
func (r Request) PreVerificationGas() Gas            { return r.preVerificationGas }
func (r Request) PaymasterVerificationGasLimit() Gas { return r.paymasterVerificationGas }
func (r Request) PaymasterPostOpGasLimit() Gas       { return r.paymasterPostOpGas }
func (r Request) MaxFeePerGas() Fee                  { return r.maxFee }
func (r Request) MaxPriorityFeePerGas() Fee          { return r.maxPriorityFee }
func (r Request) RequestedLifetime() (uint64, bool) {
	return r.requestedLifetimeSeconds, r.lifetimeProvided
}

// CanonicalInput persists the normalized draft that admission evaluated.
func (r Request) CanonicalInput() RequestInput {
	input := RequestInput{
		ChainID: r.chainID.String(), EntryPoint: r.entryPoint.String(), Sender: r.sender.String(), Nonce: r.nonce.String(),
		CallData: "0x" + hex.EncodeToString(r.outerCallData), CallGasLimit: r.callGas.String(),
		VerificationGasLimit: r.verificationGas.String(), PreVerificationGas: r.preVerificationGas.String(),
		PaymasterVerificationGasLimit: r.paymasterVerificationGas.String(), PaymasterPostOpGasLimit: r.paymasterPostOpGas.String(),
		MaxFeePerGas: r.maxFee.String(), MaxPriorityFeePerGas: r.maxPriorityFee.String(),
	}
	if r.lifetimeProvided {
		input.RequestedLifetimeSeconds = fmt.Sprintf("%d", r.requestedLifetimeSeconds)
	}
	return input
}
func (r Request) Call() Call {
	c := r.call
	c.data = bytes.Clone(c.data)
	return c
}

type NormalizationError struct {
	Reason Reason
	Err    error
}

func (e *NormalizationError) Error() string { return e.Err.Error() }
func (e *NormalizationError) Unwrap() error { return e.Err }

func normalizeError(reason Reason, format string, args ...any) error {
	return &NormalizationError{Reason: reason, Err: fmt.Errorf(format, args...)}
}

func Normalize(input RequestInput) (Request, error) {
	var out Request
	chain, err := ParseUint256(input.ChainID)
	if err != nil || chain.IsZero() {
		return out, normalizeError(ReasonMalformedRequest, "invalid chain ID")
	}
	out.chainID = ChainID{chain}
	if out.entryPoint, err = ParseAddress(input.EntryPoint); err != nil || out.entryPoint.IsZero() {
		return Request{}, normalizeError(ReasonMalformedRequest, "invalid EntryPoint address")
	}
	if out.sender, err = ParseAddress(input.Sender); err != nil || out.sender.IsZero() {
		return Request{}, normalizeError(ReasonMalformedRequest, "invalid sender address")
	}
	nonce, err := ParseUint256(input.Nonce)
	if err != nil {
		return Request{}, normalizeError(ReasonMalformedRequest, "invalid nonce")
	}
	out.nonce = Nonce{nonce}
	if !strings.HasPrefix(input.CallData, "0x") || len(input.CallData)%2 != 0 {
		return Request{}, normalizeError(ReasonMalformedRequest, "invalid calldata hex")
	}
	if len(input.CallData) > 2+maxAccountCallDataBytes*2 {
		return Request{}, normalizeError(ReasonMalformedRequest, "calldata too large")
	}
	out.outerCallData, err = hex.DecodeString(input.CallData[2:])
	if err != nil {
		return Request{}, normalizeError(ReasonMalformedRequest, "invalid calldata hex")
	}
	out.call, err = DecodeExecute(out.outerCallData)
	if err != nil {
		return Request{}, normalizeError(ReasonUnsupportedCallShape, "unsupported account call: %w", err)
	}
	fields := []struct {
		name  string
		value string
		set   func(Uint256)
	}{
		{"call gas", input.CallGasLimit, func(v Uint256) { out.callGas = Gas{v} }},
		{"verification gas", input.VerificationGasLimit, func(v Uint256) { out.verificationGas = Gas{v} }},
		{"pre-verification gas", input.PreVerificationGas, func(v Uint256) { out.preVerificationGas = Gas{v} }},
		{"paymaster verification gas", input.PaymasterVerificationGasLimit, func(v Uint256) { out.paymasterVerificationGas = Gas{v} }},
		{"paymaster post-operation gas", input.PaymasterPostOpGasLimit, func(v Uint256) { out.paymasterPostOpGas = Gas{v} }},
		{"max fee", input.MaxFeePerGas, func(v Uint256) { out.maxFee = Fee{v} }},
		{"max priority fee", input.MaxPriorityFeePerGas, func(v Uint256) { out.maxPriorityFee = Fee{v} }},
	}
	for _, field := range fields {
		v, parseErr := ParseUint256(field.value)
		if parseErr != nil || !v.withinEntryPointGasRange() {
			return Request{}, normalizeError(ReasonMalformedRequest, "invalid %s quantity", field.name)
		}
		field.set(v)
	}
	if out.callGas.IsZero() || out.verificationGas.IsZero() || out.preVerificationGas.IsZero() || out.paymasterVerificationGas.IsZero() || out.maxFee.IsZero() {
		return Request{}, normalizeError(ReasonMalformedRequest, "required gas or fee quantity is zero")
	}
	if input.RequestedLifetimeSeconds != "" {
		lifetime, parseErr := ParseUint256(input.RequestedLifetimeSeconds)
		if parseErr != nil {
			return Request{}, normalizeError(ReasonMalformedRequest, "invalid requested lifetime")
		}
		var ok bool
		out.requestedLifetimeSeconds, ok = lifetime.Uint64()
		if !ok {
			return Request{}, normalizeError(ReasonMalformedRequest, "requested lifetime overflows uint64")
		}
		out.lifetimeProvided = true
	}
	out.valid = true
	return out, nil
}

func ReasonForNormalization(err error) Reason {
	var normalized *NormalizationError
	if errors.As(err, &normalized) {
		return normalized.Reason
	}
	return ReasonMalformedRequest
}
