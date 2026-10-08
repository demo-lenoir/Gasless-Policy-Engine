package userop

import (
	"errors"
	"math/big"

	"github.com/demo-lenoir/gasless-policy-engine/internal/authorization"
	"github.com/demo-lenoir/gasless-policy-engine/internal/issuance"
	"github.com/demo-lenoir/gasless-policy-engine/internal/policy"
	"github.com/demo-lenoir/gasless-policy-engine/internal/signing"
	"github.com/ethereum/go-ethereum/common"
)

// Packed is the v0.9 PackedUserOperation ABI tuple. AccountSignature is supplied by the account owner.
type Packed struct {
	Sender             common.Address
	Nonce              *big.Int
	InitCode           []byte
	CallData           []byte
	AccountGasLimits   [32]byte
	PreVerificationGas *big.Int
	GasFees            [32]byte
	PaymasterAndData   []byte
	Signature          []byte
}

func Build(request policy.Request, artifact issuance.Artifact) (Packed, error) {
	if request.ChainID() != artifact.ChainID || request.EntryPoint() != artifact.EntryPoint ||
		artifact.SponsorshipID == [32]byte{} || artifact.PolicyVersion == 0 {
		return Packed{}, errors.New("request and authorization identity differ")
	}
	amount, ok := policy.EstimatedUpperBound(request)
	if !ok {
		return Packed{}, errors.New("operation cost upper bound overflow")
	}
	auth, err := authorization.Build(request, artifact.SponsorshipID, artifact.PolicyVersion,
		artifact.PolicyHash, artifact.AccountCodeHash, amount.Uint256, artifact.ValidAfter, artifact.ValidUntil)
	if err != nil {
		return Packed{}, err
	}
	domain, err := authorization.NewDomain(artifact.ChainID, artifact.Paymaster)
	if err != nil {
		return Packed{}, err
	}
	digest, err := authorization.Digest(domain, auth)
	if err != nil || digest != artifact.Digest {
		return Packed{}, errors.New("authorization digest differs from normalized operation")
	}
	if err := signing.VerifySignature(digest, artifact.Signature[:], artifact.Signer); err != nil {
		return Packed{}, err
	}
	encoded, err := authorization.EncodePaymasterAndData(domain, auth, artifact.Signature[:])
	if err != nil || len(encoded) != len(artifact.PaymasterAndData) {
		return Packed{}, errors.New("invalid paymaster encoding")
	}
	for i := range encoded {
		if encoded[i] != artifact.PaymasterAndData[i] {
			return Packed{}, errors.New("paymaster encoding differs from durable artifact")
		}
	}
	sender := request.Sender()
	return Packed{
		Sender: common.BytesToAddress(sender[:]), Nonce: request.Nonce().Big(),
		InitCode: []byte{}, CallData: request.OuterCallData(),
		AccountGasLimits: auth.AccountGasLimits, PreVerificationGas: request.PreVerificationGas().Big(),
		GasFees: auth.GasFees, PaymasterAndData: append([]byte(nil), encoded...),
	}, nil
}

func (op Packed) WithAccountSignature(signature []byte) Packed {
	op.InitCode = append([]byte(nil), op.InitCode...)
	op.CallData = append([]byte(nil), op.CallData...)
	op.PaymasterAndData = append([]byte(nil), op.PaymasterAndData...)
	op.Signature = append([]byte(nil), signature...)
	if op.Nonce != nil {
		op.Nonce = new(big.Int).Set(op.Nonce)
	}
	if op.PreVerificationGas != nil {
		op.PreVerificationGas = new(big.Int).Set(op.PreVerificationGas)
	}
	return op
}
