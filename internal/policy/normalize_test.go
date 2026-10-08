package policy

import (
	"encoding/hex"
	"math/big"
	"reflect"
	"strings"
	"testing"
)

func TestNormalizeDeterministicAndCanonical(t *testing.T) {
	input := testInput(t)
	first, err := Normalize(input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Normalize(input)
	if err != nil || !reflect.DeepEqual(first, second) {
		t.Fatalf("normalization changed: %v", err)
	}
	input.Sender = strings.ToUpper(input.Sender[2:])
	input.Sender = "0x" + input.Sender
	input.CallData = "0x" + strings.ToUpper(input.CallData[2:])
	canonical, err := Normalize(input)
	if err != nil || !reflect.DeepEqual(first, canonical) {
		t.Fatalf("equivalent hex did not normalize equally: %v", err)
	}
	if canonical.Sender().String() != testSender || canonical.Call().Selector.String() != "0x12345678" {
		t.Fatal("incorrect derived subject")
	}
	returned := canonical.OuterCallData()
	returned[0] = 0
	if canonical.OuterCallData()[0] != 0xb6 {
		t.Fatal("request exposed mutable calldata")
	}
}

func TestNormalizeRejectsMalformedInput(t *testing.T) {
	base := testInput(t)
	tooLarge := new(big.Int).Add(maxUint256, big.NewInt(1)).String()
	gasTooLarge := new(big.Int).Add(maxEntryPointGasValue, big.NewInt(1)).String()
	cases := []struct {
		name   string
		change func(*RequestInput)
		reason Reason
	}{
		{"zero chain", func(r *RequestInput) { r.ChainID = "0" }, ReasonMalformedRequest},
		{"negative chain", func(r *RequestInput) { r.ChainID = "-1" }, ReasonMalformedRequest},
		{"leading zero chain", func(r *RequestInput) { r.ChainID = "031337" }, ReasonMalformedRequest},
		{"chain overflow", func(r *RequestInput) { r.ChainID = tooLarge }, ReasonMalformedRequest},
		{"invalid EntryPoint", func(r *RequestInput) { r.EntryPoint = "0x1234" }, ReasonMalformedRequest},
		{"invalid sender", func(r *RequestInput) { r.Sender = "0xgggggggggggggggggggggggggggggggggggggggg" }, ReasonMalformedRequest},
		{"nonce overflow", func(r *RequestInput) { r.Nonce = tooLarge }, ReasonMalformedRequest},
		{"negative gas", func(r *RequestInput) { r.CallGasLimit = "-1" }, ReasonMalformedRequest},
		{"gas over v09 range", func(r *RequestInput) { r.CallGasLimit = gasTooLarge }, ReasonMalformedRequest},
		{"gas uint256 overflow", func(r *RequestInput) { r.PreVerificationGas = tooLarge }, ReasonMalformedRequest},
		{"zero gas", func(r *RequestInput) { r.VerificationGasLimit = "0" }, ReasonMalformedRequest},
		{"fee leading zero", func(r *RequestInput) { r.MaxFeePerGas = "01" }, ReasonMalformedRequest},
		{"lifetime overflow", func(r *RequestInput) { r.RequestedLifetimeSeconds = tooLarge }, ReasonMalformedRequest},
		{"odd calldata hex", func(r *RequestInput) { r.CallData = "0x123" }, ReasonMalformedRequest},
		{"bad calldata hex", func(r *RequestInput) { r.CallData = "0xzz" }, ReasonMalformedRequest},
		{"short calldata", func(r *RequestInput) { r.CallData = "0x12345678" }, ReasonUnsupportedCallShape},
		{"wrong account selector", func(r *RequestInput) { r.CallData = "0x00000000" + r.CallData[10:] }, ReasonUnsupportedCallShape},
		{"unsupported batch", func(r *RequestInput) { r.CallData = "0x47e1da2a" + r.CallData[10:] }, ReasonUnsupportedCallShape},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := base
			tc.change(&input)
			if _, err := Normalize(input); err == nil || ReasonForNormalization(err) != tc.reason {
				t.Fatalf("got err %v, reason %s", err, ReasonForNormalization(err))
			}
		})
	}
	badTarget := base
	raw, _ := hex.DecodeString(base.CallData[2:])
	clear(raw[4+12 : 4+32])
	badTarget.CallData = "0x" + hex.EncodeToString(raw)
	if _, err := Normalize(badTarget); err == nil || ReasonForNormalization(err) != ReasonUnsupportedCallShape {
		t.Fatal("zero target accepted")
	}
}
