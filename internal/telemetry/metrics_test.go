package telemetry

import (
	"testing"
	"time"

	"github.com/demo-lenoir/gasless-policy-engine/internal/issuance"
	"github.com/prometheus/client_golang/prometheus"
)

func TestSigningMetricsTrackCommittedOutcome(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics, err := New(registry)
	if err != nil {
		t.Fatal(err)
	}
	metrics.SigningCompleted(issuance.Issued, time.Millisecond)
	metrics.SigningCompleted(issuance.AlreadyIssued, time.Millisecond)
	metrics.SigningCompleted(issuance.EmergencyDisabled, time.Millisecond)
	metrics.SigningCompleted(issuance.SignerTimeout, time.Millisecond)
	metricFamilies, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var active, signing, signerErrors float64
	for _, family := range metricFamilies {
		switch family.GetName() {
		case "gasless_artifacts_active":
			for _, sample := range family.Metric {
				active += sample.GetGauge().GetValue()
			}
		case "gasless_signing_total":
			for _, sample := range family.Metric {
				signing += sample.GetCounter().GetValue()
			}
		case "gasless_signer_errors_total":
			for _, sample := range family.Metric {
				signerErrors += sample.GetCounter().GetValue()
			}
		}
	}
	if active != 1 || signing != 4 || signerErrors != 1 {
		t.Fatalf("active=%v signing=%v signerErrors=%v", active, signing, signerErrors)
	}
	metrics.ArtifactExpired(1)
	metricFamilies, err = registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range metricFamilies {
		if family.GetName() == "gasless_artifacts_active" && family.Metric[0].GetGauge().GetValue() != 0 {
			t.Fatal("elapsed artifact retained as active")
		}
	}
}
