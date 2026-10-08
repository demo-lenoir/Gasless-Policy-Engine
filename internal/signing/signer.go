package signing

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"math/big"

	"github.com/demo-lenoir/gasless-policy-engine/internal/policy"
	"github.com/ethereum/go-ethereum/crypto"
)

// SponsorSigner receives only a canonical digest assembled after durable admission.
type SponsorSigner interface {
	Address(context.Context) (policy.Address, error)
	SignDigest(context.Context, [32]byte) ([]byte, error)
}

type DevLocalSigner struct{ key *ecdsa.PrivateKey }

// NewDevLocalSigner requires explicit development configuration. No runtime loader is provided.
func NewDevLocalSigner(key *ecdsa.PrivateKey, developmentMode bool) (*DevLocalSigner, error) {
	if !developmentMode || key == nil || key.D == nil {
		return nil, errors.New("development signer is unavailable")
	}
	return &DevLocalSigner{key: key}, nil
}

func (s *DevLocalSigner) Address(ctx context.Context) (policy.Address, error) {
	if err := ctx.Err(); err != nil {
		return policy.Address{}, err
	}
	if s == nil || s.key == nil {
		return policy.Address{}, errors.New("signer unavailable")
	}
	return policy.Address(crypto.PubkeyToAddress(s.key.PublicKey)), nil
}

func (s *DevLocalSigner) SignDigest(ctx context.Context, digest [32]byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s == nil || s.key == nil {
		return nil, errors.New("signer unavailable")
	}
	sig, err := crypto.Sign(digest[:], s.key)
	if err != nil {
		return nil, errors.New("signer unavailable")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sig[64] += 27
	return sig, nil
}

func VerifySignature(digest [32]byte, sig []byte, expected policy.Address) error {
	if expected.IsZero() || len(sig) != 65 || (sig[64] != 27 && sig[64] != 28) {
		return errors.New("invalid signature encoding")
	}
	v := sig[64] - 27
	if !crypto.ValidateSignatureValues(v, newBig(sig[:32]), newBig(sig[32:64]), true) {
		return errors.New("noncanonical signature")
	}
	canonical := append([]byte(nil), sig...)
	canonical[64] = v
	pub, err := crypto.SigToPub(digest[:], canonical)
	if err != nil || pub == nil {
		return errors.New("invalid signature")
	}
	actual := policy.Address(crypto.PubkeyToAddress(*pub))
	if actual != expected {
		return errors.New("signer identity mismatch")
	}
	return nil
}

func newBig(raw []byte) *big.Int { return new(big.Int).SetBytes(raw) }
