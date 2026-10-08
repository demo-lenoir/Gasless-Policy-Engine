package telemetry

import (
	"context"
	"math/big"
	"time"

	"github.com/demo-lenoir/gasless-policy-engine/internal/admission"
	"github.com/demo-lenoir/gasless-policy-engine/internal/issuance"
	"github.com/demo-lenoir/gasless-policy-engine/internal/store"
	"github.com/prometheus/client_golang/prometheus"
)

type Metrics struct {
	requests         *prometheus.CounterVec
	policySeconds    prometheus.Histogram
	reserved         prometheus.Gauge
	expired          prometheus.Counter
	estimatedWei     prometheus.Gauge
	remainingWei     prometheus.Gauge
	retries          prometheus.Counter
	signing          *prometheus.CounterVec
	signerErrors     *prometheus.CounterVec
	signingTime      prometheus.Histogram
	activeArtifacts  prometheus.Gauge
	consumed         prometheus.Counter
	actualWei        prometheus.Gauge
	releasedWei      prometheus.Gauge
	reconciliation   *prometheus.CounterVec
	reorgs           prometheus.Counter
	lagBlocks        prometheus.Gauge
	paymasterBalance prometheus.Gauge
}

func New(reg prometheus.Registerer) (*Metrics, error) {
	m := &Metrics{
		requests:         prometheus.NewCounterVec(prometheus.CounterOpts{Name: "gasless_requests_total", Help: "Admission calls by bounded decision and reason."}, []string{"decision", "reason"}),
		policySeconds:    prometheus.NewHistogram(prometheus.HistogramOpts{Name: "gasless_policy_eval_seconds", Help: "Static policy evaluation time.", Buckets: prometheus.DefBuckets}),
		reserved:         prometheus.NewGauge(prometheus.GaugeOpts{Name: "gasless_sponsorships_reserved", Help: "Locally observed active reservations; refresh from the ledger after restart."}),
		expired:          prometheus.NewCounter(prometheus.CounterOpts{Name: "gasless_sponsorships_expired_total", Help: "Committed reservation expirations observed by this process."}),
		estimatedWei:     prometheus.NewGauge(prometheus.GaugeOpts{Name: "gasless_estimated_spend_wei", Help: "Approximate cumulative admitted upper bounds observed by this process; exact amounts remain in PostgreSQL."}),
		remainingWei:     prometheus.NewGauge(prometheus.GaugeOpts{Name: "gasless_daily_budget_remaining_wei", Help: "Approximate all-chain remaining Wei for the most recently observed period; PostgreSQL is authoritative."}),
		retries:          prometheus.NewCounter(prometheus.CounterOpts{Name: "gasless_db_transaction_retries_total", Help: "Admission retries after serialization or deadlock errors."}),
		signing:          prometheus.NewCounterVec(prometheus.CounterOpts{Name: "gasless_signing_total", Help: "Signing attempts by bounded result and reason."}, []string{"result", "reason"}),
		signerErrors:     prometheus.NewCounterVec(prometheus.CounterOpts{Name: "gasless_signer_errors_total", Help: "Signer failures by bounded reason."}, []string{"reason"}),
		signingTime:      prometheus.NewHistogram(prometheus.HistogramOpts{Name: "gasless_signing_seconds", Help: "Authorization issuance duration.", Buckets: prometheus.DefBuckets}),
		activeArtifacts:  prometheus.NewGauge(prometheus.GaugeOpts{Name: "gasless_artifacts_active", Help: "Issued authorizations still inside the validity window; refresh from PostgreSQL."}),
		consumed:         prometheus.NewCounter(prometheus.CounterOpts{Name: "gasless_sponsorships_consumed_total", Help: "Committed finalized consumption observed by this process."}),
		actualWei:        prometheus.NewGauge(prometheus.GaugeOpts{Name: "gasless_actual_spend_wei", Help: "Approximate finalized sponsor spend; PostgreSQL is authoritative."}),
		releasedWei:      prometheus.NewGauge(prometheus.GaugeOpts{Name: "gasless_budget_released_wei", Help: "Approximate capacity returned from finalized or unused reservations."}),
		reconciliation:   prometheus.NewCounterVec(prometheus.CounterOpts{Name: "gasless_reconciliation_events_total", Help: "Committed reconciliation outcomes by bounded result."}, []string{"result"}),
		reorgs:           prometheus.NewCounter(prometheus.CounterOpts{Name: "gasless_reorgs_total", Help: "Canonical branch changes processed by this watcher."}),
		lagBlocks:        prometheus.NewGauge(prometheus.GaugeOpts{Name: "gasless_reconciliation_lag_blocks", Help: "Observed head minus durable scanned checkpoint."}),
		paymasterBalance: prometheus.NewGauge(prometheus.GaugeOpts{Name: "gasless_paymaster_balance_wei", Help: "Approximate EntryPoint paymaster deposit from the latest RPC observation."}),
	}
	for _, c := range []prometheus.Collector{m.requests, m.policySeconds, m.reserved, m.expired, m.estimatedWei, m.remainingWei, m.retries, m.signing, m.signerErrors, m.signingTime, m.activeArtifacts, m.consumed, m.actualWei, m.releasedWei, m.reconciliation, m.reorgs, m.lagBlocks, m.paymasterBalance} {
		if err := reg.Register(c); err != nil {
			return nil, err
		}
	}
	return m, nil
}
func (m *Metrics) PaymasterBalance(raw string)     { m.paymasterBalance.Set(approximate(raw)) }
func (m *Metrics) PolicyEvaluated(d time.Duration) { m.policySeconds.Observe(d.Seconds()) }
func (m *Metrics) AdmissionRetry()                 { m.retries.Inc() }
func (m *Metrics) RefreshFromLedger(ctx context.Context, p *store.Postgres, now time.Time, configuredGlobalWei string) error {
	snapshot, err := p.ReadLedgerMetrics(ctx, now)
	if err != nil {
		return err
	}
	m.reserved.Set(float64(snapshot.ReservedCount))
	m.activeArtifacts.Set(float64(snapshot.ActiveArtifacts))
	m.estimatedWei.Set(approximate(snapshot.EstimatedSpendWei))
	m.actualWei.Set(approximate(snapshot.ActualSpendWei))
	m.releasedWei.Set(approximate(snapshot.ReleasedWei))
	if snapshot.DailyBudgetRemainingWei != "" {
		m.remainingWei.Set(approximate(snapshot.DailyBudgetRemainingWei))
	} else {
		m.remainingWei.Set(approximate(configuredGlobalWei))
	}
	return nil
}
func (m *Metrics) SigningCompleted(reason issuance.Reason, elapsed time.Duration) {
	label := string(reason)
	switch reason {
	case issuance.Issued, issuance.AlreadyIssued, issuance.SigningInProgress, issuance.EmergencyDisabled, issuance.PolicyRevoked, issuance.PolicyVersionConflict, issuance.AuthorizationExpired, issuance.ReservationStateConflict, issuance.SigningClaimLost, issuance.SignerUnavailable, issuance.SignerTimeout, issuance.SignerIdentityMismatch, issuance.InvalidSignature, issuance.StorageUnavailable, issuance.InvalidInput:
	default:
		label = "UNKNOWN"
	}
	result := "denied"
	if reason == issuance.Issued || reason == issuance.AlreadyIssued {
		result = "issued"
	}
	if reason == issuance.StorageUnavailable || reason == issuance.SignerUnavailable || reason == issuance.SignerTimeout || reason == issuance.InvalidSignature || reason == issuance.SignerIdentityMismatch {
		result = "error"
	}
	m.signing.WithLabelValues(result, label).Inc()
	m.signingTime.Observe(elapsed.Seconds())
	if reason == issuance.Issued {
		m.activeArtifacts.Inc()
	}
	if reason == issuance.SignerUnavailable || reason == issuance.SignerTimeout || reason == issuance.SignerIdentityMismatch || reason == issuance.InvalidSignature {
		m.signerErrors.WithLabelValues(label).Inc()
	}
}
func (m *Metrics) ArtifactExpired(count int) {
	if count > 0 {
		m.activeArtifacts.Sub(float64(count))
	}
}
func (m *Metrics) AdmissionCompleted(r admission.Result) {
	reason := "UNKNOWN"
	switch r.Reason {
	case admission.Approved, admission.StaticPolicyDenied, admission.QuotaExhausted, admission.GlobalBudgetExhausted, admission.ChainBudgetExhausted, admission.IdempotencyConflict, admission.ReservationExpired, admission.ReservationStateConflict, admission.StorageUnavailable, admission.InvalidRequest, admission.EmergencyDisabled, admission.PolicyVersionConflict:
		reason = string(r.Reason)
	}
	decision := "denied"
	if r.Approved {
		decision = "approved"
	}
	if r.Reason == admission.StorageUnavailable || r.Reason == admission.PolicyVersionConflict {
		decision = "error"
	}
	m.requests.WithLabelValues(decision, reason).Inc()
	if r.Approved && !r.Replayed {
		m.reserved.Inc()
		m.estimatedWei.Add(approximate(r.EstimatedUpperBoundWei))
		m.remainingWei.Set(approximate(r.GlobalBudgetRemainingWei))
	}
}
func (m *Metrics) ReservationTransition(status store.Transition, remaining string) {
	m.reserved.Dec()
	if status == store.Consumed {
		m.consumed.Inc()
		m.reconciliation.WithLabelValues("consumed").Inc()
	}
	if status == store.Expired {
		m.expired.Inc()
		m.reconciliation.WithLabelValues("expired").Inc()
	}
	m.remainingWei.Set(approximate(remaining))
}
func (m *Metrics) ReconciliationProgress(head, checkpoint uint64, reorg bool) {
	if head >= checkpoint {
		m.lagBlocks.Set(float64(head - checkpoint))
	}
	if reorg {
		m.reorgs.Inc()
		m.reconciliation.WithLabelValues("reorged").Inc()
	}
}
func approximate(raw string) float64 {
	v, ok := new(big.Int).SetString(raw, 10)
	if !ok {
		return 0
	}
	f, _ := new(big.Float).SetInt(v).Float64()
	return f
}
