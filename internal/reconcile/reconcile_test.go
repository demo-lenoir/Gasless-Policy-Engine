package reconcile

import (
	"math/big"
	"testing"

	"github.com/demo-lenoir/gasless-policy-engine/internal/policy"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

func testStream(t *testing.T) Stream {
	t.Helper()
	chain, _ := policy.ParseUint256("31337")
	entry, _ := policy.ParseAddress("0x433709009b8330fda32311df1c2afa402ed8d009")
	paymaster, _ := policy.ParseAddress("0x3333333333333333333333333333333333333333")
	return Stream{ChainID: policy.ChainID{Uint256: chain}, EntryPoint: entry, Paymaster: paymaster, ID: "v09", Confirmations: 3, MaxReorgDepth: 8, MaxBlocks: 100}
}

func TestConfirmationBoundary(t *testing.T) {
	for _, tc := range []struct{ head, event, want uint64 }{{1, 3, 0}, {3, 3, 1}, {4, 3, 2}, {5, 3, 3}, {6, 3, 4}} {
		if got := Confirmations(tc.head, tc.event); got != tc.want {
			t.Fatalf("head=%d event=%d: %d", tc.head, tc.event, got)
		}
	}
}

func TestEntryPointEventIdentity(t *testing.T) {
	s := testStream(t)
	data := make([]byte, 128)
	big.NewInt(7).FillBytes(data[:32])
	big.NewInt(123).FillBytes(data[64:96])
	big.NewInt(456).FillBytes(data[96:128])
	sender := common.HexToAddress("0x2222222222222222222222222222222222222222")
	log := types.Log{Address: common.Address(s.EntryPoint), Topics: []common.Hash{EventTopic, common.HexToHash("0x01"), common.BytesToHash(sender[:]), common.BytesToHash(s.Paymaster[:])}, Data: data, BlockHash: common.HexToHash("0x02"), TxHash: common.HexToHash("0x03"), BlockNumber: 2}
	e, err := DecodeEvent(log, s)
	if err != nil || e.Success || e.ActualGasCost.String() != "123" || e.Nonce.String() != "7" {
		t.Fatalf("event %+v: %v", e, err)
	}
	changed := log
	changed.Topics = append([]common.Hash(nil), log.Topics...)
	changed.Topics[3] = common.HexToHash("0x04")
	if _, err := DecodeEvent(changed, s); err == nil {
		t.Fatal("wrong paymaster accepted")
	}
	changed = log
	changed.Address = common.HexToAddress("0x1111111111111111111111111111111111111111")
	if _, err := DecodeEvent(changed, s); err == nil {
		t.Fatal("wrong EntryPoint accepted")
	}
	changed = log
	changed.Data = append([]byte(nil), log.Data...)
	changed.Data[63] = 2
	if _, err := DecodeEvent(changed, s); err == nil {
		t.Fatal("malformed boolean accepted")
	}
	changed = log
	changed.Data = append([]byte(nil), log.Data...)
	changed.Data[63] = 1
	e, err = DecodeEvent(changed, s)
	if err != nil || !e.Success {
		t.Fatalf("success event %+v: %v", e, err)
	}
}
