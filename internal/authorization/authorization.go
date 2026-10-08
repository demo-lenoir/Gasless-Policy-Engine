package authorization

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/demo-lenoir/gasless-policy-engine/internal/policy"
	"github.com/ethereum/go-ethereum/crypto"
)

const DomainName = "GaslessPolicyEngine"
const DomainVersion = "1"
const SponsorshipType = "Sponsorship(bytes32 sponsorshipId,uint64 policyVersion,bytes32 policyHash,address entryPoint,address sender,bytes32 accountCodeHash,uint256 nonce,bytes32 initCodeHash,bytes32 callDataHash,bytes32 accountGasLimits,uint256 preVerificationGas,bytes32 gasFees,uint128 paymasterVerificationGasLimit,uint128 paymasterPostOpGasLimit,uint256 maxSponsorCostWei,uint48 validAfter,uint48 validUntil)"
const domainType = "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
const maxTimestamp = uint64(1<<47 - 1)

var sponsorshipTypeHash = keccak([]byte(SponsorshipType))
var domainTypeHash = keccak([]byte(domainType))
var emptyInitCodeHash = keccak(nil)

type Domain struct {
	ChainID   policy.ChainID
	Paymaster policy.Address
}

func NewDomain(chain policy.ChainID, paymaster policy.Address) (Domain, error) {
	if chain.IsZero() || paymaster.IsZero() {
		return Domain{}, errors.New("chain and paymaster are required")
	}
	return Domain{chain, paymaster}, nil
}

type Sponsorship struct {
	SponsorshipID                 [32]byte
	PolicyVersion                 uint64
	PolicyHash                    [32]byte
	EntryPoint                    policy.Address
	Sender                        policy.Address
	AccountCodeHash               [32]byte
	Nonce                         policy.Uint256
	InitCodeHash                  [32]byte
	CallDataHash                  [32]byte
	AccountGasLimits              [32]byte
	PreVerificationGas            policy.Uint256
	GasFees                       [32]byte
	PaymasterVerificationGasLimit policy.Uint256
	PaymasterPostOpGasLimit       policy.Uint256
	MaxSponsorCostWei             policy.Uint256
	ValidAfter                    uint64
	ValidUntil                    uint64
}

// Build uses the admitted request and reservation fields; initCode is empty in the fixed-account flow.
func Build(r policy.Request, id [32]byte, version policy.PolicyVersion, policyHash, accountCodeHash [32]byte, cost policy.Uint256, after, until time.Time) (Sponsorship, error) {
	if id == [32]byte{} || version == 0 || policyHash == [32]byte{} || accountCodeHash == [32]byte{} {
		return Sponsorship{}, errors.New("missing authorization identity")
	}
	if after.Nanosecond() != 0 || until.Nanosecond() != 0 || after.Unix() <= 0 || until.Unix() <= after.Unix() || uint64(until.Unix()) > maxTimestamp {
		return Sponsorship{}, errors.New("invalid timestamp validity")
	}
	expected, ok := policy.EstimatedUpperBound(r)
	if !ok || expected.Uint256 != cost || cost.IsZero() {
		return Sponsorship{}, errors.New("reservation cost differs from approved upper bound")
	}
	accountGas, err := pack128(r.VerificationGasLimit().Uint256, r.CallGasLimit().Uint256)
	if err != nil {
		return Sponsorship{}, err
	}
	gasFees, err := pack128(r.MaxPriorityFeePerGas().Uint256, r.MaxFeePerGas().Uint256)
	if err != nil {
		return Sponsorship{}, err
	}
	if !fits128(r.PaymasterVerificationGasLimit().Uint256) || !fits128(r.PaymasterPostOpGasLimit().Uint256) {
		return Sponsorship{}, errors.New("paymaster gas exceeds uint128")
	}
	out := Sponsorship{SponsorshipID: id, PolicyVersion: uint64(version), PolicyHash: policyHash, EntryPoint: r.EntryPoint(), Sender: r.Sender(), AccountCodeHash: accountCodeHash, Nonce: r.Nonce().Uint256, InitCodeHash: emptyInitCodeHash, CallDataHash: keccak(r.OuterCallData()), AccountGasLimits: accountGas, PreVerificationGas: r.PreVerificationGas().Uint256, GasFees: gasFees, PaymasterVerificationGasLimit: r.PaymasterVerificationGasLimit().Uint256, PaymasterPostOpGasLimit: r.PaymasterPostOpGasLimit().Uint256, MaxSponsorCostWei: cost, ValidAfter: uint64(after.Unix()), ValidUntil: uint64(until.Unix())}
	if err := out.Validate(); err != nil {
		return Sponsorship{}, err
	}
	return out, nil
}

func (a Sponsorship) Validate() error {
	if a.SponsorshipID == [32]byte{} || a.PolicyVersion == 0 || a.PolicyHash == [32]byte{} || a.EntryPoint.IsZero() || a.Sender.IsZero() || a.AccountCodeHash == [32]byte{} || a.MaxSponsorCostWei.IsZero() {
		return errors.New("missing authorization field")
	}
	if a.InitCodeHash != emptyInitCodeHash {
		return errors.New("unsupported initCode")
	}
	if a.CallDataHash == [32]byte{} || a.AccountGasLimits == [32]byte{} || a.GasFees == [32]byte{} || a.PreVerificationGas.IsZero() || a.PaymasterVerificationGasLimit.IsZero() {
		return errors.New("missing operation commitment")
	}
	if a.ValidAfter == 0 || a.ValidUntil <= a.ValidAfter || a.ValidUntil > maxTimestamp {
		return errors.New("invalid authorization validity")
	}
	if !fits128(a.PaymasterVerificationGasLimit) || !fits128(a.PaymasterPostOpGasLimit) {
		return errors.New("paymaster gas exceeds uint128")
	}
	if !a.PaymasterPostOpGasLimit.IsZero() {
		return errors.New("post-operation gas unsupported in fixed-account flow")
	}
	if new(big.Int).SetBytes(a.AccountGasLimits[:16]).Sign() == 0 || new(big.Int).SetBytes(a.AccountGasLimits[16:]).Sign() == 0 || new(big.Int).SetBytes(a.GasFees[16:]).Sign() == 0 || new(big.Int).SetBytes(a.GasFees[:16]).Cmp(new(big.Int).SetBytes(a.GasFees[16:])) > 0 {
		return errors.New("invalid packed gas or fee values")
	}
	return nil
}

func (d Domain) Separator() ([32]byte, error) { return domainSeparator(d, DomainVersion) }
func domainSeparator(d Domain, version string) ([32]byte, error) {
	if d.ChainID.IsZero() || d.Paymaster.IsZero() || version == "" {
		return [32]byte{}, errors.New("invalid sponsorship domain")
	}
	var encoded [160]byte
	copy(encoded[0:32], domainTypeHash[:])
	name := keccak([]byte(DomainName))
	copy(encoded[32:64], name[:])
	v := keccak([]byte(version))
	copy(encoded[64:96], v[:])
	chain := d.ChainID.Bytes32()
	copy(encoded[96:128], chain[:])
	copy(encoded[140:160], d.Paymaster[:])
	return keccak(encoded[:]), nil
}

func (a Sponsorship) StructHash() ([32]byte, error) {
	if err := a.Validate(); err != nil {
		return [32]byte{}, err
	}
	words := [18][32]byte{}
	words[0] = sponsorshipTypeHash
	words[1] = a.SponsorshipID
	binary.BigEndian.PutUint64(words[2][24:], a.PolicyVersion)
	words[3] = a.PolicyHash
	copy(words[4][12:], a.EntryPoint[:])
	copy(words[5][12:], a.Sender[:])
	words[6] = a.AccountCodeHash
	words[7] = a.Nonce.Bytes32()
	words[8] = a.InitCodeHash
	words[9] = a.CallDataHash
	words[10] = a.AccountGasLimits
	words[11] = a.PreVerificationGas.Bytes32()
	words[12] = a.GasFees
	words[13] = a.PaymasterVerificationGasLimit.Bytes32()
	words[14] = a.PaymasterPostOpGasLimit.Bytes32()
	words[15] = a.MaxSponsorCostWei.Bytes32()
	binary.BigEndian.PutUint64(words[16][24:], a.ValidAfter)
	binary.BigEndian.PutUint64(words[17][24:], a.ValidUntil)
	encoded := make([]byte, 0, len(words)*32)
	for _, w := range words {
		encoded = append(encoded, w[:]...)
	}
	return keccak(encoded), nil
}

func Digest(d Domain, a Sponsorship) ([32]byte, error) {
	separator, err := d.Separator()
	if err != nil {
		return [32]byte{}, err
	}
	hash, err := a.StructHash()
	if err != nil {
		return [32]byte{}, err
	}
	payload := make([]byte, 0, 66)
	payload = append(payload, 0x19, 0x01)
	payload = append(payload, separator[:]...)
	payload = append(payload, hash[:]...)
	return keccak(payload), nil
}

func fits128(v policy.Uint256) bool {
	b := v.Bytes32()
	for _, x := range b[:16] {
		if x != 0 {
			return false
		}
	}
	return true
}
func pack128(high, low policy.Uint256) ([32]byte, error) {
	if !fits128(high) || !fits128(low) {
		return [32]byte{}, errors.New("packed quantity exceeds uint128")
	}
	var out [32]byte
	h := high.Bytes32()
	l := low.Bytes32()
	copy(out[:16], h[16:])
	copy(out[16:], l[16:])
	return out, nil
}
func keccak(data []byte) [32]byte { hash := crypto.Keccak256Hash(data); return [32]byte(hash) }

func ParseSponsorshipID(raw []byte) ([32]byte, error) {
	if len(raw) != 32 {
		return [32]byte{}, fmt.Errorf("sponsorship ID has %d bytes", len(raw))
	}
	var out [32]byte
	copy(out[:], raw)
	if out == [32]byte{} {
		return [32]byte{}, errors.New("zero sponsorship ID")
	}
	return out, nil
}
