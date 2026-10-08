package policy

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// Uint256 keeps Ethereum quantities as values, with checked conversions.
type Uint256 struct{ bytes [32]byte }

type ChainID struct{ Uint256 }
type Nonce struct{ Uint256 }
type Wei struct{ Uint256 }
type Gas struct{ Uint256 }
type Fee struct{ Uint256 }
type PolicyVersion uint64
type Address [20]byte
type Selector [4]byte

var maxUint256 = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
var maxEntryPointGasValue = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 120), big.NewInt(1))

func ParseUint256(s string) (Uint256, error) {
	if s == "" || len(s) > 78 || (len(s) > 1 && s[0] == '0') {
		return Uint256{}, errors.New("noncanonical decimal quantity")
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return Uint256{}, errors.New("noncanonical decimal quantity")
		}
	}
	n, ok := new(big.Int).SetString(s, 10)
	if !ok || n.Sign() < 0 || n.Cmp(maxUint256) > 0 {
		return Uint256{}, errors.New("quantity exceeds uint256")
	}
	return uint256FromBig(n), nil
}

func uint256FromBig(n *big.Int) Uint256 {
	var out Uint256
	n.FillBytes(out.bytes[:])
	return out
}

func (n Uint256) Big() *big.Int         { return new(big.Int).SetBytes(n.bytes[:]) }
func (n Uint256) String() string        { return n.Big().String() }
func (n Uint256) Bytes32() [32]byte     { return n.bytes }
func (n Uint256) IsZero() bool          { return n == Uint256{} }
func (n Uint256) Cmp(other Uint256) int { return n.Big().Cmp(other.Big()) }

func (n Uint256) Uint64() (uint64, bool) {
	b := n.Big()
	if !b.IsUint64() {
		return 0, false
	}
	return b.Uint64(), true
}

func (n Uint256) Add(other Uint256) (Uint256, bool) {
	sum := new(big.Int).Add(n.Big(), other.Big())
	if sum.Cmp(maxUint256) > 0 {
		return Uint256{}, false
	}
	return uint256FromBig(sum), true
}

func (n Uint256) Mul(other Uint256) (Uint256, bool) {
	product := new(big.Int).Mul(n.Big(), other.Big())
	if product.Cmp(maxUint256) > 0 {
		return Uint256{}, false
	}
	return uint256FromBig(product), true
}

func (n Uint256) withinEntryPointGasRange() bool {
	return n.Big().Cmp(maxEntryPointGasValue) <= 0
}

func ParseAddress(s string) (Address, error) {
	var out Address
	if len(s) != 42 || !strings.HasPrefix(s, "0x") {
		return out, errors.New("address must be 20 hex bytes")
	}
	b, err := hex.DecodeString(s[2:])
	if err != nil {
		return out, fmt.Errorf("invalid address hex: %w", err)
	}
	copy(out[:], b)
	return out, nil
}

func (a Address) String() string { return "0x" + hex.EncodeToString(a[:]) }
func (a Address) IsZero() bool   { return a == Address{} }

func ParseSelector(s string) (Selector, error) {
	var out Selector
	if len(s) != 10 || !strings.HasPrefix(s, "0x") {
		return out, errors.New("selector must be 4 hex bytes")
	}
	b, err := hex.DecodeString(s[2:])
	if err != nil {
		return out, fmt.Errorf("invalid selector hex: %w", err)
	}
	copy(out[:], b)
	return out, nil
}

func (s Selector) String() string { return "0x" + hex.EncodeToString(s[:]) }
