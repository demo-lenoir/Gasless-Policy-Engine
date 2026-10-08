package authorization

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/demo-lenoir/gasless-policy-engine/internal/policy"
	"github.com/demo-lenoir/gasless-policy-engine/internal/signing"
)

type fixtureReporter interface {
	Helper()
	Fatal(...any)
}

func requestFixture(t fixtureReporter) policy.Request {
	t.Helper()
	inner := []byte{0x12, 0x34, 0x56, 0x78, 0xaa}
	outer := make([]byte, 4+96+32+32)
	copy(outer[:4], []byte{0xb6, 0x1d, 0x27, 0xf6})
	for i := 16; i < 36; i++ {
		outer[i] = 0x11
	}
	outer[4+95] = 96
	binary.BigEndian.PutUint64(outer[4+96+24:4+96+32], uint64(len(inner)))
	copy(outer[4+96+32:], inner)
	r, err := policy.Normalize(policy.RequestInput{ChainID: "31337", EntryPoint: "0x433709009b8330fda32311df1c2afa402ed8d009", Sender: "0x2222222222222222222222222222222222222222", Nonce: "7", CallData: "0x" + hex.EncodeToString(outer), CallGasLimit: "100000", VerificationGasLimit: "100000", PreVerificationGas: "30000", PaymasterVerificationGasLimit: "80000", PaymasterPostOpGasLimit: "0", MaxFeePerGas: "10000000000", MaxPriorityFeePerGas: "1000000000"})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func authFixture(t fixtureReporter) (Domain, Sponsorship) {
	t.Helper()
	r := requestFixture(t)
	paymaster, _ := policy.ParseAddress("0x3333333333333333333333333333333333333333")
	domain, _ := NewDomain(r.ChainID(), paymaster)
	var id, policyHash, accountHash [32]byte
	id[31] = 1
	policyHash[31] = 2
	accountHash[31] = 3
	cost, _ := policy.EstimatedUpperBound(r)
	a, err := Build(r, id, 1, policyHash, accountHash, cost.Uint256, time.Unix(1893542400, 0), time.Unix(1893542460, 0))
	if err != nil {
		t.Fatal(err)
	}
	return domain, a
}

func TestDigestBindsEveryField(t *testing.T) {
	d, a := authFixture(t)
	original, err := Digest(d, a)
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*Sponsorship){
		"sponsorship_id":             func(v *Sponsorship) { v.SponsorshipID[0] ^= 1 },
		"policy_version":             func(v *Sponsorship) { v.PolicyVersion++ },
		"policy_hash":                func(v *Sponsorship) { v.PolicyHash[0] ^= 1 },
		"entry_point":                func(v *Sponsorship) { v.EntryPoint[0] ^= 1 },
		"sender":                     func(v *Sponsorship) { v.Sender[0] ^= 1 },
		"account_code_hash":          func(v *Sponsorship) { v.AccountCodeHash[0] ^= 1 },
		"nonce":                      func(v *Sponsorship) { v.Nonce, _ = policy.ParseUint256("8") },
		"call_data_hash":             func(v *Sponsorship) { v.CallDataHash[0] ^= 1 },
		"verification_gas":           func(v *Sponsorship) { v.AccountGasLimits[15] ^= 1 },
		"call_gas":                   func(v *Sponsorship) { v.AccountGasLimits[31] ^= 1 },
		"pre_verification_gas":       func(v *Sponsorship) { v.PreVerificationGas, _ = policy.ParseUint256("30001") },
		"priority_fee":               func(v *Sponsorship) { v.GasFees[15] ^= 1 },
		"max_fee":                    func(v *Sponsorship) { v.GasFees[31] ^= 1 },
		"paymaster_verification_gas": func(v *Sponsorship) { v.PaymasterVerificationGasLimit, _ = policy.ParseUint256("80001") },
		"paymaster_postop_gas":       func(v *Sponsorship) { v.PaymasterPostOpGasLimit, _ = policy.ParseUint256("1") },
		"max_cost":                   func(v *Sponsorship) { v.MaxSponsorCostWei, _ = policy.ParseUint256("3100000000000001") },
		"valid_after":                func(v *Sponsorship) { v.ValidAfter++ },
		"valid_until":                func(v *Sponsorship) { v.ValidUntil++ },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := a
			mutate(&changed)
			got, err := Digest(d, changed)
			if err != nil {
				return
			}
			if got == original {
				t.Fatal("mutation preserved digest")
			}
		})
	}
	otherChain := d
	otherChain.ChainID.Uint256, _ = policy.ParseUint256("31338")
	otherPaymaster := d
	otherPaymaster.Paymaster[0] ^= 1
	for name, domain := range map[string]Domain{"chain": otherChain, "paymaster": otherPaymaster} {
		t.Run(name, func(t *testing.T) {
			got, err := Digest(domain, a)
			if err != nil || got == original {
				t.Fatalf("domain mutation: %x %v", got, err)
			}
		})
	}
	otherVersion, err := domainSeparator(d, "2")
	if err != nil {
		t.Fatal(err)
	}
	originalVersion, _ := d.Separator()
	if otherVersion == originalVersion {
		t.Fatal("domain version mutation preserved separator")
	}
}

func TestCanonicalAccountCallMutation(t *testing.T) {
	domain, base := authFixture(t)
	original, _ := Digest(domain, base)
	input := requestFixture(t).CanonicalInput()
	outer, err := hex.DecodeString(strings.TrimPrefix(input.CallData, "0x"))
	if err != nil {
		t.Fatal(err)
	}
	for name, offset := range map[string]int{
		"target":     16,
		"value":      4 + 63,
		"selector":   4 + 96 + 32,
		"inner_data": 4 + 96 + 36,
	} {
		t.Run(name, func(t *testing.T) {
			changed := bytes.Clone(outer)
			changed[offset] ^= 1
			input.CallData = "0x" + hex.EncodeToString(changed)
			r, err := policy.Normalize(input)
			if err != nil {
				t.Fatal(err)
			}
			amount, ok := policy.EstimatedUpperBound(r)
			if !ok {
				t.Fatal("cost overflow")
			}
			auth, err := Build(r, base.SponsorshipID, policy.PolicyVersion(base.PolicyVersion), base.PolicyHash, base.AccountCodeHash, amount.Uint256, time.Unix(int64(base.ValidAfter), 0), time.Unix(int64(base.ValidUntil), 0))
			if err != nil {
				t.Fatal(err)
			}
			digest, err := Digest(domain, auth)
			if err != nil || digest == original {
				t.Fatalf("call mutation preserved digest: %v", err)
			}
		})
	}
}

func TestPaymasterEncodingCanonical(t *testing.T) {
	d, a := authFixture(t)
	data, err := a.PaymasterData()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodePaymasterData(data[:])
	if err != nil {
		t.Fatal(err)
	}
	if decoded.SponsorshipID != a.SponsorshipID || decoded.PolicyVersion != a.PolicyVersion || decoded.PolicyHash != a.PolicyHash || decoded.MaxSponsorCostWei != a.MaxSponsorCostWei || decoded.ValidAfter != a.ValidAfter || decoded.ValidUntil != a.ValidUntil {
		t.Fatal("data roundtrip")
	}
	sig := make([]byte, 65)
	sig[31], sig[63] = 1, 1
	sig[64] = 27
	full, err := EncodePaymasterAndData(d, a, sig)
	if err != nil {
		t.Fatal(err)
	}
	if len(full) != PaymasterAndDataLength {
		t.Fatal(len(full))
	}
	parsed, err := DecodePaymasterAndData(full)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Paymaster != d.Paymaster || parsed.Data != decoded || !bytes.Equal(parsed.Signature[:], sig) {
		t.Fatal("paymasterAndData roundtrip")
	}
	for name, mutate := range map[string]func([]byte){"short": func(v []byte) {}, "length": func(v []byte) { v[234] = 64 }, "magic": func(v []byte) { v[235] ^= 1 }} {
		t.Run(name, func(t *testing.T) {
			changed := bytes.Clone(full)
			if name == "short" {
				changed = changed[:len(changed)-1]
			} else {
				mutate(changed)
			}
			if _, err := DecodePaymasterAndData(changed); err == nil {
				t.Fatal("accepted malformed encoding")
			}
		})
	}
}

func TestBuildRejectsChangedReservationAndValidity(t *testing.T) {
	r := requestFixture(t)
	_, base := authFixture(t)
	cost, ok := policy.EstimatedUpperBound(r)
	if !ok {
		t.Fatal("fixture cost")
	}
	wrongCost, ok := cost.Uint256.Add(mustQuantity(t, "1"))
	if !ok {
		t.Fatal("fixture overflow")
	}
	after := time.Unix(int64(base.ValidAfter), 0)
	until := time.Unix(int64(base.ValidUntil), 0)
	for name, params := range map[string]struct {
		cost         policy.Uint256
		after, until time.Time
		policyHash   [32]byte
	}{
		"cost":                {wrongCost, after, until, base.PolicyHash},
		"fractional_validity": {cost.Uint256, after.Add(time.Nanosecond), until, base.PolicyHash},
		"reversed_validity":   {cost.Uint256, until, after, base.PolicyHash},
		"missing_snapshot":    {cost.Uint256, after, until, [32]byte{}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Build(r, base.SponsorshipID, 1, params.policyHash, base.AccountCodeHash, params.cost, params.after, params.until); err == nil {
				t.Fatal("invalid authorization built")
			}
		})
	}
}

func mustQuantity(t *testing.T, raw string) policy.Uint256 {
	t.Helper()
	v, err := policy.ParseUint256(raw)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func FuzzPaymasterEncoding(f *testing.F) {
	raw, err := os.ReadFile("../../testdata/authorization-vector.json")
	if err != nil {
		f.Fatal(err)
	}
	var vector struct {
		PaymasterData string `json:"paymaster_data"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		f.Fatal(err)
	}
	data, err := hex.DecodeString(strings.TrimPrefix(vector.PaymasterData, "0x"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(data)
	f.Add([]byte{0, 1, 2})
	f.Fuzz(func(t *testing.T, b []byte) {
		decoded, err := DecodePaymasterData(b)
		if err != nil {
			return
		}
		if len(b) != PaymasterDataLength {
			t.Fatal("wrong length accepted")
		}
		if decoded.SponsorshipID == [32]byte{} || decoded.PolicyVersion == 0 {
			t.Fatal("invalid data accepted")
		}
	})
}

func FuzzPaymasterAndData(f *testing.F) {
	raw, err := os.ReadFile("../../testdata/authorization-vector.json")
	if err != nil {
		f.Fatal(err)
	}
	var vector struct {
		Full string `json:"paymaster_and_data"`
	}
	if err = json.Unmarshal(raw, &vector); err != nil {
		f.Fatal(err)
	}
	seed, err := hex.DecodeString(strings.TrimPrefix(vector.Full, "0x"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte{0, 1, 2})
	_, base := authFixture(f)
	f.Fuzz(func(t *testing.T, b []byte) {
		decoded, err := DecodePaymasterAndData(b)
		if err != nil {
			return
		}
		chain, _ := policy.ParseUint256("31337")
		domain, err := NewDomain(policy.ChainID{Uint256: chain}, decoded.Paymaster)
		if err != nil {
			t.Fatal(err)
		}
		a := base
		a.SponsorshipID = decoded.Data.SponsorshipID
		a.PolicyVersion = decoded.Data.PolicyVersion
		a.PolicyHash = decoded.Data.PolicyHash
		a.MaxSponsorCostWei = decoded.Data.MaxSponsorCostWei
		a.ValidAfter = decoded.Data.ValidAfter
		a.ValidUntil = decoded.Data.ValidUntil
		a.PaymasterVerificationGasLimit = decoded.VerificationGasLimit
		a.PaymasterPostOpGasLimit = decoded.PostOpGasLimit
		reencoded, err := EncodePaymasterAndData(domain, a, decoded.Signature[:])
		if err != nil || !bytes.Equal(reencoded, b) {
			t.Fatalf("noncanonical accepted encoding: %v", err)
		}
	})
}

func TestCommittedVector(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/authorization-vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	get := func(k string) string {
		t.Helper()
		var v string
		if err := json.Unmarshal(fields[k], &v); err != nil {
			t.Fatal(k, err)
		}
		return v
	}
	match := func(k string, actual []byte) {
		t.Helper()
		if get(k) != "0x"+hex.EncodeToString(actual) {
			t.Fatalf("%s mismatch", k)
		}
	}
	d, a := authFixture(t)
	separator, _ := d.Separator()
	structHash, _ := a.StructHash()
	digest, _ := Digest(d, a)
	match("domain_separator", separator[:])
	match("struct_hash", structHash[:])
	match("digest", digest[:])
	match("sponsorship_id", a.SponsorshipID[:])
	match("policy_hash", a.PolicyHash[:])
	match("account_code_hash", a.AccountCodeHash[:])
	match("init_code_hash", a.InitCodeHash[:])
	match("call_data_hash", a.CallDataHash[:])
	match("account_gas_limits", a.AccountGasLimits[:])
	match("gas_fees", a.GasFees[:])
	data, _ := a.PaymasterData()
	match("paymaster_data", data[:])
	sig, err := hex.DecodeString(strings.TrimPrefix(get("signature"), "0x"))
	if err != nil {
		t.Fatal(err)
	}
	address, err := policy.ParseAddress(strings.ToLower(get("expected_signer")))
	if err != nil {
		t.Fatal(err)
	}
	if err = signing.VerifySignature(digest, sig, address); err != nil {
		t.Fatal(err)
	}
	full, err := EncodePaymasterAndData(d, a, sig)
	if err != nil {
		t.Fatal(err)
	}
	match("paymaster_and_data", full)
}
