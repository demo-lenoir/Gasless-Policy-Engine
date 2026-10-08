package issuance

import (
	"context"
	"encoding/hex"
	"errors"
	"go.opentelemetry.io/otel"
	"time"

	"github.com/demo-lenoir/gasless-policy-engine/internal/authorization"
	"github.com/demo-lenoir/gasless-policy-engine/internal/policy"
	"github.com/demo-lenoir/gasless-policy-engine/internal/signing"
)

type Reason string

const (
	Issued                   Reason = "AUTHORIZATION_ISSUED"
	AlreadyIssued            Reason = "AUTHORIZATION_ALREADY_ISSUED"
	SigningInProgress        Reason = "SIGNING_IN_PROGRESS"
	EmergencyDisabled        Reason = "EMERGENCY_DISABLED"
	PolicyRevoked            Reason = "POLICY_VERSION_REVOKED"
	PolicyVersionConflict    Reason = "POLICY_VERSION_CONFLICT"
	AuthorizationExpired     Reason = "AUTHORIZATION_EXPIRED"
	ReservationStateConflict Reason = "RESERVATION_STATE_CONFLICT"
	SigningClaimLost         Reason = "SIGNING_CLAIM_LOST"
	SignerUnavailable        Reason = "SIGNER_UNAVAILABLE"
	SignerTimeout            Reason = "SIGNER_TIMEOUT"
	SignerIdentityMismatch   Reason = "SIGNER_IDENTITY_MISMATCH"
	InvalidSignature         Reason = "INVALID_SIGNATURE"
	StorageUnavailable       Reason = "STORAGE_UNAVAILABLE"
	InvalidInput             Reason = "INVALID_INPUT"
)

type Claim struct {
	Token         string
	Generation    int64
	SponsorshipID [32]byte
	RequestID     string
	Input         policy.RequestInput
	Fingerprint   [32]byte
	PolicyVersion policy.PolicyVersion
	PolicyHash    [32]byte
	ReservedWei   policy.Uint256
	ValidAfter    time.Time
	ValidUntil    time.Time
	Profile       Profile
}

type Profile struct {
	PolicyVersion   policy.PolicyVersion
	ChainID         policy.ChainID
	Paymaster       policy.Address
	EntryPoint      policy.Address
	AccountCodeHash [32]byte
	ExpectedSigner  policy.Address
}

type Artifact struct {
	SponsorshipID    [32]byte
	RequestID        string
	PolicyVersion    policy.PolicyVersion
	PolicyHash       [32]byte
	ChainID          policy.ChainID
	EntryPoint       policy.Address
	Paymaster        policy.Address
	Signer           policy.Address
	AccountCodeHash  [32]byte
	ValidAfter       time.Time
	ValidUntil       time.Time
	Digest           [32]byte
	Signature        [65]byte
	PaymasterData    [authorization.PaymasterDataLength]byte
	PaymasterAndData [authorization.PaymasterAndDataLength]byte
}

type ClaimResult struct {
	Reason   Reason
	Claim    Claim
	Artifact *Artifact
}

type Repository interface {
	ClaimSigning(context.Context, [32]byte, Profile, time.Time, time.Duration) (ClaimResult, error)
	CheckSigningClaim(context.Context, Claim, time.Time) (Reason, error)
	CommitAuthorization(context.Context, Claim, Artifact, time.Time) (Reason, error)
	FailSigningClaim(context.Context, Claim, Reason, time.Time) error
	ReadAuthorization(context.Context, [32]byte) (*Artifact, error)
}

type Config struct {
	PolicyVersion   policy.PolicyVersion
	ChainID         policy.ChainID
	Paymaster       policy.Address
	EntryPoint      policy.Address
	AccountCodeHash [32]byte
	ExpectedSigner  policy.Address
	ClaimLease      time.Duration
	SignerTimeout   time.Duration
}

func (c Config) Validate() error {
	if c.PolicyVersion == 0 || c.ChainID.IsZero() || c.Paymaster.IsZero() || c.EntryPoint.IsZero() || c.AccountCodeHash == [32]byte{} || c.ExpectedSigner.IsZero() || c.ClaimLease <= 0 || c.SignerTimeout <= 0 || c.SignerTimeout >= c.ClaimLease {
		return errors.New("invalid issuance configuration")
	}
	return nil
}

func (c Config) Profile() Profile {
	return Profile{c.PolicyVersion, c.ChainID, c.Paymaster, c.EntryPoint, c.AccountCodeHash, c.ExpectedSigner}
}

type Observer interface{ SigningCompleted(Reason, time.Duration) }

type Service struct {
	cfg      Config
	repo     Repository
	signer   signing.SponsorSigner
	now      func() time.Time
	observer Observer
}

func NewService(cfg Config, repo Repository, signer signing.SponsorSigner, now func() time.Time) (*Service, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if repo == nil || signer == nil || now == nil {
		return nil, errors.New("repository, signer and clock are required")
	}
	return &Service{cfg: cfg, repo: repo, signer: signer, now: now}, nil
}

func (s *Service) SetObserver(o Observer) { s.observer = o }

// Issue accepts only the durable sponsorship ID; no caller-supplied digest reaches the signer.
func (s *Service) Issue(ctx context.Context, sponsorshipID string) (Artifact, Reason, error) {
	ctx, span := otel.Tracer("gasless/issuance").Start(ctx, "issuance.claim_sign_commit")
	defer span.End()
	started := time.Now()
	finish := func(a Artifact, reason Reason, err error) (Artifact, Reason, error) {
		if s.observer != nil {
			s.observer.SigningCompleted(reason, time.Since(started))
		}
		return a, reason, err
	}
	raw, err := hex.DecodeString(sponsorshipID)
	if err != nil || len(raw) != 32 {
		return finish(Artifact{}, InvalidInput, nil)
	}
	var id [32]byte
	copy(id[:], raw)
	if id == [32]byte{} {
		return finish(Artifact{}, InvalidInput, nil)
	}
	for {
		result, err := s.repo.ClaimSigning(ctx, id, s.cfg.Profile(), s.now().UTC(), s.cfg.ClaimLease)
		if err != nil {
			return finish(Artifact{}, StorageUnavailable, err)
		}
		if result.Artifact != nil {
			return finish(*result.Artifact, AlreadyIssued, nil)
		}
		if result.Reason == SigningInProgress {
			select {
			case <-ctx.Done():
				return finish(Artifact{}, SigningInProgress, ctx.Err())
			case <-time.After(10 * time.Millisecond):
				continue
			}
		}
		if result.Reason != Issued {
			return finish(Artifact{}, result.Reason, nil)
		}
		claim := result.Claim
		if claim.PolicyVersion != s.cfg.PolicyVersion {
			return s.fail(ctx, claim, PolicyVersionConflict, finish)
		}
		r, err := policy.Normalize(claim.Input)
		if err != nil {
			return s.fail(ctx, claim, ReservationStateConflict, finish)
		}
		if r.ChainID() != s.cfg.ChainID || r.EntryPoint() != s.cfg.EntryPoint {
			return s.fail(ctx, claim, PolicyVersionConflict, finish)
		}
		domain, err := authorization.NewDomain(r.ChainID(), s.cfg.Paymaster)
		if err != nil {
			return s.fail(ctx, claim, InvalidInput, finish)
		}
		auth, err := authorization.Build(r, claim.SponsorshipID, claim.PolicyVersion, claim.PolicyHash, s.cfg.AccountCodeHash, claim.ReservedWei, claim.ValidAfter, claim.ValidUntil)
		if err != nil {
			return s.fail(ctx, claim, ReservationStateConflict, finish)
		}
		digest, err := authorization.Digest(domain, auth)
		if err != nil {
			return s.fail(ctx, claim, InvalidInput, finish)
		}
		addressCtx, cancel := context.WithTimeout(ctx, s.cfg.SignerTimeout)
		address, err := s.signer.Address(addressCtx)
		addressContextErr := addressCtx.Err()
		cancel()
		if addressContextErr != nil {
			return s.signerFailure(ctx, claim, addressContextErr, finish)
		}
		if err != nil {
			return s.signerFailure(ctx, claim, err, finish)
		}
		if address != s.cfg.ExpectedSigner {
			return s.fail(ctx, claim, SignerIdentityMismatch, finish)
		}
		pre, err := s.repo.CheckSigningClaim(ctx, claim, s.now().UTC())
		if err != nil {
			return finish(Artifact{}, StorageUnavailable, err)
		}
		if pre != Issued {
			return s.fail(ctx, claim, pre, finish)
		}
		signCtx, cancel := context.WithTimeout(ctx, s.cfg.SignerTimeout)
		signCtx, signerSpan := otel.Tracer("gasless/signing").Start(signCtx, "signer.sign_digest")
		sig, err := s.signer.SignDigest(signCtx, digest)
		signerSpan.End()
		signContextErr := signCtx.Err()
		cancel()
		if signContextErr != nil {
			return s.signerFailure(ctx, claim, signContextErr, finish)
		}
		if err != nil {
			return s.signerFailure(ctx, claim, err, finish)
		}
		if err := signing.VerifySignature(digest, sig, s.cfg.ExpectedSigner); err != nil {
			return s.fail(ctx, claim, InvalidSignature, finish)
		}
		data, err := auth.PaymasterData()
		if err != nil {
			return s.fail(ctx, claim, InvalidInput, finish)
		}
		encoded, err := authorization.EncodePaymasterAndData(domain, auth, sig)
		if err != nil {
			return s.fail(ctx, claim, InvalidInput, finish)
		}
		artifact := Artifact{SponsorshipID: id, RequestID: claim.RequestID, PolicyVersion: claim.PolicyVersion, PolicyHash: claim.PolicyHash, ChainID: r.ChainID(), EntryPoint: r.EntryPoint(), Paymaster: s.cfg.Paymaster, Signer: s.cfg.ExpectedSigner, AccountCodeHash: s.cfg.AccountCodeHash, ValidAfter: claim.ValidAfter, ValidUntil: claim.ValidUntil, Digest: digest, PaymasterData: data}
		copy(artifact.Signature[:], sig)
		copy(artifact.PaymasterAndData[:], encoded)
		reason, err := s.repo.CommitAuthorization(ctx, claim, artifact, s.now().UTC())
		if err != nil {
			return finish(Artifact{}, StorageUnavailable, err)
		}
		if reason != Issued {
			return s.fail(ctx, claim, reason, finish)
		}
		return finish(artifact, Issued, nil)
	}
}

func (s *Service) fail(ctx context.Context, c Claim, r Reason, finish func(Artifact, Reason, error) (Artifact, Reason, error)) (Artifact, Reason, error) {
	if err := s.repo.FailSigningClaim(ctx, c, r, s.now().UTC()); err != nil {
		return finish(Artifact{}, StorageUnavailable, err)
	}
	return finish(Artifact{}, r, nil)
}
func (s *Service) signerFailure(ctx context.Context, c Claim, err error, finish func(Artifact, Reason, error) (Artifact, Reason, error)) (Artifact, Reason, error) {
	r := SignerUnavailable
	if errors.Is(err, context.DeadlineExceeded) {
		r = SignerTimeout
	}
	return s.fail(ctx, c, r, finish)
}
