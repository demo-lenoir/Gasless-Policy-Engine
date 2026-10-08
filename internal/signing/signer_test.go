package signing

import (
	"context"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

func TestDevSignerCanonicalSignature(t *testing.T) {
	// Scalar one is public fixture material; it is never used by runtime configuration.
	var scalar [32]byte
	scalar[31] = 1
	key, err := crypto.ToECDSA(scalar[:])
	if err != nil {
		t.Fatal(err)
	}
	if _, err = NewDevLocalSigner(key, false); err == nil {
		t.Fatal("development gate missing")
	}
	signer, err := NewDevLocalSigner(key, true)
	if err != nil {
		t.Fatal(err)
	}
	address, err := signer.Address(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var digest [32]byte
	digest[31] = 42
	sig, err := signer.SignDigest(context.Background(), digest)
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifySignature(digest, sig, address); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func([]byte) []byte{
		"short":        func(s []byte) []byte { return s[:64] },
		"wrong_v":      func(s []byte) []byte { s[64] = 0; return s },
		"zero_r":       func(s []byte) []byte { clear(s[:32]); return s },
		"wrong_signer": func(s []byte) []byte { s[10] ^= 1; return s },
		"high_s": func(s []byte) []byte {
			n := crypto.S256().Params().N
			value := new(big.Int).SetBytes(s[32:64])
			high := new(big.Int).Sub(n, value)
			high.FillBytes(s[32:64])
			return s
		},
	} {
		t.Run(name, func(t *testing.T) {
			modified := mutate(append([]byte(nil), sig...))
			if err := VerifySignature(digest, modified, address); err == nil {
				t.Fatal("accepted malformed signature")
			}
		})
	}
	wrongDigest := digest
	wrongDigest[0] ^= 1
	if err = VerifySignature(wrongDigest, sig, address); err == nil {
		t.Fatal("accepted wrong digest")
	}
}
