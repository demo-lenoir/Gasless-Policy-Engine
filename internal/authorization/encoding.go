package authorization

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/big"

	"github.com/demo-lenoir/gasless-policy-engine/internal/policy"
	"github.com/ethereum/go-ethereum/crypto"
)

const PaymasterDataLength = 116
const PaymasterAndDataLength = 20 + 16 + 16 + PaymasterDataLength + 65 + 2 + 8

var signatureMagic = [8]byte{0x22, 0xe3, 0x25, 0xa2, 0x97, 0x43, 0x96, 0x56}

// PaymasterData carries values that cannot be recovered from PackedUserOperation.
func (a Sponsorship) PaymasterData() ([PaymasterDataLength]byte, error) {
	var out [PaymasterDataLength]byte
	if err := a.Validate(); err != nil {
		return out, err
	}
	copy(out[0:32], a.SponsorshipID[:])
	binary.BigEndian.PutUint64(out[32:40], a.PolicyVersion)
	copy(out[40:72], a.PolicyHash[:])
	cost := a.MaxSponsorCostWei.Bytes32()
	copy(out[72:104], cost[:])
	put48(out[104:110], a.ValidAfter)
	put48(out[110:116], a.ValidUntil)
	return out, nil
}

func put48(dst []byte, v uint64) {
	for i := 5; i >= 0; i-- {
		dst[i] = byte(v)
		v >>= 8
	}
}

func read48(src []byte) uint64 {
	var out uint64
	for _, b := range src {
		out = out<<8 | uint64(b)
	}
	return out
}

type DecodedPaymasterData struct {
	SponsorshipID     [32]byte
	PolicyVersion     uint64
	PolicyHash        [32]byte
	MaxSponsorCostWei policy.Uint256
	ValidAfter        uint64
	ValidUntil        uint64
}

func DecodePaymasterData(raw []byte) (DecodedPaymasterData, error) {
	var out DecodedPaymasterData
	if len(raw) != PaymasterDataLength {
		return out, errors.New("invalid paymaster data length")
	}
	copy(out.SponsorshipID[:], raw[0:32])
	out.PolicyVersion = binary.BigEndian.Uint64(raw[32:40])
	copy(out.PolicyHash[:], raw[40:72])
	cost, err := policy.ParseUint256(bytesToDecimal(raw[72:104]))
	if err != nil {
		return DecodedPaymasterData{}, err
	}
	out.MaxSponsorCostWei = cost
	out.ValidAfter = read48(raw[104:110])
	out.ValidUntil = read48(raw[110:116])
	if out.SponsorshipID == [32]byte{} || out.PolicyVersion == 0 || out.PolicyHash == [32]byte{} || out.MaxSponsorCostWei.IsZero() || out.ValidAfter == 0 || out.ValidUntil <= out.ValidAfter || out.ValidUntil > maxTimestamp {
		return DecodedPaymasterData{}, errors.New("invalid paymaster data values")
	}
	return out, nil
}

func bytesToDecimal(b []byte) string { return new(big.Int).SetBytes(b).String() }

func EncodePaymasterAndData(domain Domain, auth Sponsorship, signature []byte) ([]byte, error) {
	if domain.Paymaster.IsZero() || domain.ChainID.IsZero() || !validSignatureShape(signature) {
		return nil, errors.New("invalid paymaster encoding input")
	}
	data, err := auth.PaymasterData()
	if err != nil {
		return nil, err
	}
	if !fits128(auth.PaymasterVerificationGasLimit) || !fits128(auth.PaymasterPostOpGasLimit) {
		return nil, errors.New("paymaster gas exceeds uint128")
	}
	out := make([]byte, PaymasterAndDataLength)
	copy(out[:20], domain.Paymaster[:])
	verification := auth.PaymasterVerificationGasLimit.Bytes32()
	postOp := auth.PaymasterPostOpGasLimit.Bytes32()
	copy(out[20:36], verification[16:])
	copy(out[36:52], postOp[16:])
	copy(out[52:168], data[:])
	copy(out[168:233], signature)
	binary.BigEndian.PutUint16(out[233:235], 65)
	copy(out[235:], signatureMagic[:])
	return out, nil
}

type DecodedPaymasterAndData struct {
	Paymaster            policy.Address
	VerificationGasLimit policy.Uint256
	PostOpGasLimit       policy.Uint256
	Data                 DecodedPaymasterData
	Signature            [65]byte
}

func DecodePaymasterAndData(raw []byte) (DecodedPaymasterAndData, error) {
	var out DecodedPaymasterAndData
	if len(raw) != PaymasterAndDataLength || binary.BigEndian.Uint16(raw[233:235]) != 65 || !bytes.Equal(raw[235:], signatureMagic[:]) {
		return out, errors.New("invalid paymasterAndData layout")
	}
	copy(out.Paymaster[:], raw[:20])
	if out.Paymaster.IsZero() {
		return DecodedPaymasterAndData{}, errors.New("zero paymaster address")
	}
	var verifyBytes, postBytes [32]byte
	copy(verifyBytes[16:], raw[20:36])
	copy(postBytes[16:], raw[36:52])
	var err error
	out.VerificationGasLimit, err = policy.ParseUint256(bytesToDecimal(verifyBytes[:]))
	if err != nil {
		return DecodedPaymasterAndData{}, err
	}
	out.PostOpGasLimit, err = policy.ParseUint256(bytesToDecimal(postBytes[:]))
	if err != nil {
		return DecodedPaymasterAndData{}, err
	}
	if out.VerificationGasLimit.IsZero() || !out.PostOpGasLimit.IsZero() {
		return DecodedPaymasterAndData{}, errors.New("unsupported paymaster gas values")
	}
	out.Data, err = DecodePaymasterData(raw[52:168])
	if err != nil {
		return DecodedPaymasterAndData{}, err
	}
	copy(out.Signature[:], raw[168:233])
	if !validSignatureShape(out.Signature[:]) {
		return DecodedPaymasterAndData{}, errors.New("invalid signature shape")
	}
	return out, nil
}

func validSignatureShape(sig []byte) bool {
	if len(sig) != 65 || (sig[64] != 27 && sig[64] != 28) {
		return false
	}
	return crypto.ValidateSignatureValues(sig[64]-27, new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:64]), true)
}
