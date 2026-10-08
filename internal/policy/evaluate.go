package policy

import "time"

type Reason string

const (
	ReasonApproved                         Reason = "APPROVED"
	ReasonEmergencyDisabled                Reason = "EMERGENCY_DISABLED"
	ReasonMalformedRequest                 Reason = "MALFORMED_REQUEST"
	ReasonInvalidPolicy                    Reason = "INVALID_POLICY"
	ReasonUnsupportedCallShape             Reason = "UNSUPPORTED_CALL_SHAPE"
	ReasonChainNotAllowed                  Reason = "CHAIN_NOT_ALLOWED"
	ReasonEntryPointNotAllowed             Reason = "ENTRYPOINT_NOT_ALLOWED"
	ReasonSenderDenylisted                 Reason = "SENDER_DENYLISTED"
	ReasonTargetDenylisted                 Reason = "TARGET_DENYLISTED"
	ReasonTargetNotAllowed                 Reason = "TARGET_NOT_ALLOWED"
	ReasonSelectorNotAllowed               Reason = "SELECTOR_NOT_ALLOWED"
	ReasonCallValueExceeded                Reason = "CALL_VALUE_EXCEEDED"
	ReasonCallGasLimitExceeded             Reason = "CALL_GAS_LIMIT_EXCEEDED"
	ReasonVerificationGasLimitExceeded     Reason = "VERIFICATION_GAS_LIMIT_EXCEEDED"
	ReasonPreVerificationGasLimitExceeded  Reason = "PRE_VERIFICATION_GAS_LIMIT_EXCEEDED"
	ReasonPaymasterVerificationGasExceeded Reason = "PAYMASTER_VERIFICATION_GAS_LIMIT_EXCEEDED"
	ReasonPaymasterPostOpGasExceeded       Reason = "PAYMASTER_POST_OP_GAS_LIMIT_EXCEEDED"
	ReasonMaxFeeExceeded                   Reason = "MAX_FEE_PER_GAS_EXCEEDED"
	ReasonPriorityFeeExceeded              Reason = "MAX_PRIORITY_FEE_PER_GAS_EXCEEDED"
	ReasonEstimatedCostExceeded            Reason = "ESTIMATED_COST_EXCEEDED"
	ReasonInvalidValidity                  Reason = "INVALID_VALIDITY"
)

type EvaluationContext struct {
	Now time.Time
}

type Decision struct {
	Approved            bool
	Reason              Reason
	PolicyVersion       PolicyVersion
	EstimatedUpperBound Wei
	ValidAfter          time.Time
	ValidUntil          time.Time
	request             Request
}

func (d Decision) NormalizedRequest() Request {
	r := d.request
	r.outerCallData = r.OuterCallData()
	r.call = r.Call()
	return r
}

// EvaluateRaw retains stable denial reasons for inputs that fail normalization.
func EvaluateRaw(input RequestInput, snapshot PolicySnapshot, ctx EvaluationContext) Decision {
	if !snapshot.valid {
		return Decision{Reason: ReasonInvalidPolicy}
	}
	if !snapshot.enabled {
		return Decision{Reason: ReasonEmergencyDisabled, PolicyVersion: snapshot.version}
	}
	r, err := Normalize(input)
	if err != nil {
		return Decision{Reason: ReasonForNormalization(err), PolicyVersion: snapshot.version}
	}
	return Evaluate(r, snapshot, ctx)
}

// Evaluate uses only its arguments. Rule order is part of the public reason contract.
func Evaluate(request Request, snapshot PolicySnapshot, ctx EvaluationContext) Decision {
	if !snapshot.valid {
		return Decision{Reason: ReasonInvalidPolicy}
	}
	d := Decision{PolicyVersion: snapshot.version, request: request}
	deny := func(reason Reason) Decision {
		d.Reason = reason
		return d
	}
	if !snapshot.enabled {
		return deny(ReasonEmergencyDisabled)
	}
	if !request.valid {
		return deny(ReasonMalformedRequest)
	}
	chain, ok := snapshot.chains[request.chainID]
	if !ok {
		return deny(ReasonChainNotAllowed)
	}
	if chain.entryPoint != request.entryPoint {
		return deny(ReasonEntryPointNotAllowed)
	}
	if _, denied := snapshot.deniedSenders[request.sender]; denied {
		return deny(ReasonSenderDenylisted)
	}
	// Supported shape is established by Normalize; a zero Request never passes it.
	if _, denied := snapshot.deniedTargets[request.call.Target]; denied {
		return deny(ReasonTargetDenylisted)
	}
	selectors, ok := chain.targets[request.call.Target]
	if !ok {
		return deny(ReasonTargetNotAllowed)
	}
	if _, ok := selectors[request.call.Selector]; !ok {
		return deny(ReasonSelectorNotAllowed)
	}
	if request.call.Value.Cmp(snapshot.maxCallValue.Uint256) > 0 {
		return deny(ReasonCallValueExceeded)
	}
	if request.callGas.Cmp(snapshot.maxCallGas.Uint256) > 0 {
		return deny(ReasonCallGasLimitExceeded)
	}
	if request.verificationGas.Cmp(snapshot.maxVerificationGas.Uint256) > 0 {
		return deny(ReasonVerificationGasLimitExceeded)
	}
	if request.preVerificationGas.Cmp(snapshot.maxPreVerificationGas.Uint256) > 0 {
		return deny(ReasonPreVerificationGasLimitExceeded)
	}
	if request.paymasterVerificationGas.Cmp(snapshot.maxPaymasterVerificationGas.Uint256) > 0 {
		return deny(ReasonPaymasterVerificationGasExceeded)
	}
	if request.paymasterPostOpGas.Cmp(snapshot.maxPaymasterPostOpGas.Uint256) > 0 {
		return deny(ReasonPaymasterPostOpGasExceeded)
	}
	if request.maxFee.Cmp(snapshot.maxFee.Uint256) > 0 {
		return deny(ReasonMaxFeeExceeded)
	}
	if request.maxPriorityFee.Cmp(snapshot.maxPriorityFee.Uint256) > 0 || request.maxPriorityFee.Cmp(request.maxFee.Uint256) > 0 {
		return deny(ReasonPriorityFeeExceeded)
	}
	upper, ok := EstimatedUpperBound(request)
	if !ok || upper.Cmp(snapshot.maxEstimatedCost.Uint256) > 0 {
		return deny(ReasonEstimatedCostExceeded)
	}
	d.EstimatedUpperBound = upper
	lifetime := snapshot.defaultLifetimeSeconds
	if request.lifetimeProvided {
		lifetime = request.requestedLifetimeSeconds
	}
	if lifetime < snapshot.minLifetimeSeconds || lifetime > snapshot.maxLifetimeSeconds || ctx.Now.IsZero() {
		return deny(ReasonInvalidValidity)
	}
	seconds := ctx.Now.Unix()
	const maxTimestamp = int64(1<<47 - 1) // v0.9 high bit denotes block-number validity.
	if seconds < 0 || seconds > maxTimestamp || int64(lifetime) > maxTimestamp-seconds {
		return deny(ReasonInvalidValidity)
	}
	d.ValidAfter = time.Unix(seconds, 0).UTC()
	d.ValidUntil = time.Unix(seconds+int64(lifetime), 0).UTC()
	d.Approved = true
	d.Reason = ReasonApproved
	return d
}

// EstimatedUpperBound matches EntryPoint v0.9 required-prefund fields, with checked math.
// It is an upper bound for policy admission, not a promise of actual gas spent.
func EstimatedUpperBound(r Request) (Wei, bool) {
	if !r.valid {
		return Wei{}, false
	}
	gas := r.callGas.Uint256
	for _, part := range []Uint256{
		r.verificationGas.Uint256,
		r.preVerificationGas.Uint256,
		r.paymasterVerificationGas.Uint256,
		r.paymasterPostOpGas.Uint256,
	} {
		var ok bool
		gas, ok = gas.Add(part)
		if !ok {
			return Wei{}, false
		}
	}
	cost, ok := gas.Mul(r.maxFee.Uint256)
	if !ok {
		return Wei{}, false
	}
	return Wei{cost}, true
}
