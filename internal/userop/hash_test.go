package userop

import (
	"math/big"
	"testing"

	"github.com/demo-lenoir/gasless-policy-engine/internal/policy"
	"github.com/ethereum/go-ethereum/common"
)

func TestHashV09IdentityAndSignatureExclusion(t *testing.T) {
	chain, _ := policy.ParseUint256("31337")
	entry, _ := policy.ParseAddress("0x433709009b8330fda32311df1c2afa402ed8d009")
	op := Packed{Sender: common.HexToAddress("0x2222222222222222222222222222222222222222"), Nonce: big.NewInt(7), CallData: []byte{1, 2, 3, 4}, PreVerificationGas: big.NewInt(50000), PaymasterAndData: make([]byte, 243)}
	copy(op.PaymasterAndData[235:], paymasterSignatureMagic[:])
	op.PaymasterAndData[234] = 65
	op.PaymasterAndData[0] = 0x33
	op.AccountGasLimits[0] = 1
	op.GasFees[0] = 1
	hash, err := Hash(op, policy.ChainID{Uint256: chain}, entry)
	if err != nil {
		t.Fatal(err)
	}
	copyOp := op.WithAccountSignature([]byte{1, 2, 3})
	copyOp.PaymasterAndData[168] ^= 1
	if next, err := Hash(copyOp, policy.ChainID{Uint256: chain}, entry); err != nil || next != hash {
		t.Fatalf("signature suffix changed identity: %v", err)
	}
	copyOp = op.WithAccountSignature(nil)
	copyOp.CallData[0] ^= 1
	if next, _ := Hash(copyOp, policy.ChainID{Uint256: chain}, entry); next == hash {
		t.Fatal("calldata mutation preserved hash")
	}
	copyOp = op.WithAccountSignature(nil)
	copyOp.PaymasterAndData[52] ^= 1
	if next, _ := Hash(copyOp, policy.ChainID{Uint256: chain}, entry); next == hash {
		t.Fatal("paymaster data mutation preserved hash")
	}
	other, _ := policy.ParseUint256("31338")
	if next, _ := Hash(op, policy.ChainID{Uint256: other}, entry); next == hash {
		t.Fatal("chain mutation preserved hash")
	}
	entry[19] ^= 1
	if next, _ := Hash(op, policy.ChainID{Uint256: chain}, entry); next == hash {
		t.Fatal("EntryPoint mutation preserved hash")
	}
	op.PaymasterAndData[234] = 64
	if _, err := Hash(op, policy.ChainID{Uint256: chain}, entry); err == nil {
		t.Fatal("malformed signature suffix accepted")
	}
}
