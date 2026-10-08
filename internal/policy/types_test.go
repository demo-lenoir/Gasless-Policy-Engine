package policy

import (
	"math/big"
	"testing"
)

func TestUint256ParsingAndCheckedArithmetic(t *testing.T) {
	max := maxUint256.String()
	for _, tc := range []struct {
		input string
		valid bool
	}{
		{"0", true}, {"1", true}, {max, true},
		{"", false}, {"00", false}, {"01", false}, {"-1", false}, {"+1", false}, {"1.0", false}, {"0x1", false},
		{new(big.Int).Add(maxUint256, big.NewInt(1)).String(), false},
	} {
		t.Run(tc.input, func(t *testing.T) {
			got, err := ParseUint256(tc.input)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, err=%v", tc.valid, err)
			}
			if tc.valid && got.String() != tc.input {
				t.Fatalf("round trip %q", got.String())
			}
		})
	}
	maximum, _ := ParseUint256(max)
	one, _ := ParseUint256("1")
	if _, ok := maximum.Add(one); ok {
		t.Fatal("uint256 addition wrapped")
	}
	if _, ok := maximum.Mul(one); !ok {
		t.Fatal("multiplication by one failed")
	}
	if _, ok := maximum.Mul(maximum); ok {
		t.Fatal("uint256 multiplication wrapped")
	}
	if _, ok := maximum.Uint64(); ok {
		t.Fatal("uint256 narrowed to uint64")
	}
}

func TestAddressAndSelectorParsing(t *testing.T) {
	address, err := ParseAddress("0xABCDEFabcdefABCDEFabcdefABCDEFabcdefABCD")
	if err != nil || address.String() != "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd" {
		t.Fatalf("canonical address: %s, %v", address, err)
	}
	for _, raw := range []string{"0x1", "0Xabcdefabcdefabcdefabcdefabcdefabcdefabcd", "0xzzcdefabcdefabcdefabcdefabcdefabcdefabcd"} {
		if _, err := ParseAddress(raw); err == nil {
			t.Fatalf("accepted malformed address %q", raw)
		}
	}
	selector, err := ParseSelector("0xABCD1234")
	if err != nil || selector.String() != "0xabcd1234" {
		t.Fatalf("canonical selector: %s, %v", selector, err)
	}
	for _, raw := range []string{"0x123", "0x1234567890", "0xgggggggg"} {
		if _, err := ParseSelector(raw); err == nil {
			t.Fatalf("accepted malformed selector %q", raw)
		}
	}
}
