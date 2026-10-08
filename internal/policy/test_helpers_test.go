package policy

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"
)

const (
	testSender       = "0x2222222222222222222222222222222222222222"
	testDeniedSender = "0x3333333333333333333333333333333333333333"
	testTarget       = "0x1111111111111111111111111111111111111111"
	testOtherTarget  = "0x4444444444444444444444444444444444444444"
	testEntryPoint   = "0x433709009B8330FDa32311DF1C2AFA402eD8D009"
)

func testConfig(t *testing.T) Config {
	t.Helper()
	data, err := os.ReadFile("../../config/policy.example.json")
	if err != nil {
		t.Fatal(err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func testSnapshot(t *testing.T) PolicySnapshot {
	t.Helper()
	data, err := os.ReadFile("../../config/policy.example.json")
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := ReadSnapshotJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func testInput(t *testing.T) RequestInput {
	t.Helper()
	target, err := ParseAddress(testTarget)
	if err != nil {
		t.Fatal(err)
	}
	call := Call{Target: target, Selector: Selector{0x12, 0x34, 0x56, 0x78}, data: []byte{0x12, 0x34, 0x56, 0x78, 0xaa}}
	return RequestInput{
		ChainID: "31337", EntryPoint: testEntryPoint, Sender: testSender, Nonce: "7",
		CallData:     "0x" + hex.EncodeToString(encodeExecute(call)),
		CallGasLimit: "100000", VerificationGasLimit: "100000", PreVerificationGas: "30000",
		MaxFeePerGas: "10000000000", MaxPriorityFeePerGas: "1000000000",
		PaymasterVerificationGasLimit: "80000", PaymasterPostOpGasLimit: "0",
	}
}

func testContext() EvaluationContext {
	return EvaluationContext{Now: time.Unix(1_800_000_000, 0).UTC()}
}
