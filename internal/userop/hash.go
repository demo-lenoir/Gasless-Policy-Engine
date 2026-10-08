package userop

import (
	"errors"
	"math/big"

	"github.com/demo-lenoir/gasless-policy-engine/internal/policy"
	"github.com/ethereum/go-ethereum/crypto"
)

var packedTypeHash = crypto.Keccak256Hash([]byte("PackedUserOperation(address sender,uint256 nonce,bytes initCode,bytes callData,bytes32 accountGasLimits,uint256 preVerificationGas,bytes32 gasFees,bytes paymasterAndData)"))
var domainTypeHash = crypto.Keccak256Hash([]byte("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"))
var paymasterSignatureMagic = [8]byte{0x22, 0xe3, 0x25, 0xa2, 0x97, 0x43, 0x96, 0x56}

// Hash reproduces EntryPoint v0.9 getUserOpHash for the fixed deployed-account flow.
// The account signature and the paymaster signature suffix are excluded by the pinned v0.9 ABI.
func Hash(op Packed, chain policy.ChainID, entry policy.Address) ([32]byte, error) {
	if chain.IsZero() || entry.IsZero() || op.Sender == [20]byte{} || !validUint256(op.Nonce) ||
		!validUint256(op.PreVerificationGas) || len(op.InitCode) != 0 || len(op.PaymasterAndData) != 243 {
		return [32]byte{}, errors.New("unsupported UserOperation identity")
	}
	data := op.PaymasterAndData
	if data[233] != 0 || data[234] != 65 || string(data[235:]) != string(paymasterSignatureMagic[:]) {
		return [32]byte{}, errors.New("unsupported paymaster signature suffix")
	}
	words := [9][32]byte{}
	words[0] = packedTypeHash
	copy(words[1][12:], op.Sender[:])
	op.Nonce.FillBytes(words[2][:])
	words[3] = crypto.Keccak256Hash(op.InitCode)
	words[4] = crypto.Keccak256Hash(op.CallData)
	words[5] = op.AccountGasLimits
	op.PreVerificationGas.FillBytes(words[6][:])
	words[7] = op.GasFees
	signedPaymaster := make([]byte, 0, 176)
	signedPaymaster = append(signedPaymaster, data[:168]...)
	signedPaymaster = append(signedPaymaster, paymasterSignatureMagic[:]...)
	words[8] = crypto.Keccak256Hash(signedPaymaster)
	var encoded [9 * 32]byte
	for i, w := range words {
		copy(encoded[i*32:], w[:])
	}
	structHash := crypto.Keccak256Hash(encoded[:])
	var domain [5 * 32]byte
	copy(domain[:32], domainTypeHash[:])
	name := crypto.Keccak256Hash([]byte("ERC4337"))
	version := crypto.Keccak256Hash([]byte("1"))
	copy(domain[32:64], name[:])
	copy(domain[64:96], version[:])
	chain.Big().FillBytes(domain[96:128])
	copy(domain[140:160], entry[:])
	separator := crypto.Keccak256Hash(domain[:])
	return crypto.Keccak256Hash([]byte{0x19, 0x01}, separator[:], structHash[:]), nil
}

func validUint256(n *big.Int) bool { return n != nil && n.Sign() >= 0 && n.BitLen() <= 256 }
