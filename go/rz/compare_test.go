package rz

import (
	"strings"
	"testing"
	"time"
)

func utc2026(month time.Month, day, hour, min int) int64 {
	return time.Date(2026, month, day, hour, min, 0, 0, time.UTC).UnixMilli()
}

func mkTouch(over func(*NaiveTouch)) NaiveTouch {
	t := NaiveTouch{
		EventID:            "e",
		Flow:               FlowFailedSubscription,
		CustomerID:         "c",
		Reason:             ReasonInsufficientFunds,
		Attempt:            0,
		TouchesForCustomer: 0,
		Channel:            "api",
		Now:                utc2026(9, 1, 14, 30),
		DNCFlag:            false,
	}
	if over != nil {
		over(&t)
	}
	return t
}

func TestCountComplianceViolations_FraudRetry(t *testing.T) {
	v := CountComplianceViolations([]NaiveTouch{mkTouch(func(t *NaiveTouch) { t.Reason = ReasonFraudFlagged })})
	if v.FraudRetries != 1 || v.Total != 1 {
		t.Fatalf("got fraud=%d total=%d, want 1/1", v.FraudRetries, v.Total)
	}
}

func TestCountComplianceViolations_MandateRetry(t *testing.T) {
	v := CountComplianceViolations([]NaiveTouch{mkTouch(func(t *NaiveTouch) { t.Reason = ReasonMandateRevoked })})
	if v.MandateRetries != 1 || v.Total != 1 {
		t.Fatalf("got mandate=%d total=%d, want 1/1", v.MandateRetries, v.Total)
	}
}

func TestCountComplianceViolations_QuietHour(t *testing.T) {
	v := CountComplianceViolations([]NaiveTouch{mkTouch(func(t *NaiveTouch) { t.Channel = "voice"; t.Now = utc2026(9, 1, 22, 0) })})
	if v.QuietHourCalls != 1 || v.Total != 1 {
		t.Fatalf("got quiet=%d total=%d, want 1/1", v.QuietHourCalls, v.Total)
	}
}

func TestCountComplianceViolations_DncBreach(t *testing.T) {
	v := CountComplianceViolations([]NaiveTouch{mkTouch(func(t *NaiveTouch) { t.Channel = "voice"; t.DNCFlag = true; t.Now = utc2026(9, 1, 14, 0) })})
	if v.DNcBreaches != 1 || v.Total != 1 {
		t.Fatalf("got dnc=%d total=%d, want 1/1", v.DNcBreaches, v.Total)
	}
}

func TestCountComplianceViolations_TouchCap(t *testing.T) {
	v := CountComplianceViolations([]NaiveTouch{mkTouch(func(t *NaiveTouch) { t.TouchesForCustomer = 3 })})
	if v.TouchCapBreaches != 1 || v.Total != 1 {
		t.Fatalf("got touchcap=%d total=%d, want 1/1", v.TouchCapBreaches, v.Total)
	}
}

func TestCountComplianceViolations_RetryBudget(t *testing.T) {
	v := CountComplianceViolations([]NaiveTouch{mkTouch(func(t *NaiveTouch) { t.Attempt = 3 })})
	if v.RetryBudgetBreaches != 1 || v.Total != 1 {
		t.Fatalf("got budget=%d total=%d, want 1/1", v.RetryBudgetBreaches, v.Total)
	}
}

func TestCountComplianceViolations_PtpSuppression(t *testing.T) {
	ptp := utc2026(9, 5, 0, 0)
	v := CountComplianceViolations([]NaiveTouch{mkTouch(func(t *NaiveTouch) {
		t.ActivePromiseToPayDate = &ptp
		t.Now = utc2026(9, 1, 14, 0)
	})})
	if v.PtpSuppressionBreaches != 1 || v.Total != 1 {
		t.Fatalf("got ptp=%d total=%d, want 1/1", v.PtpSuppressionBreaches, v.Total)
	}
}

func TestCountComplianceViolations_UniqueUnsafeActions(t *testing.T) {
	v := CountComplianceViolations([]NaiveTouch{mkTouch(func(t *NaiveTouch) {
		t.Reason = ReasonFraudFlagged
		t.Attempt = 9
		t.TouchesForCustomer = 3
	})})
	if v.FraudRetries != 1 || v.RetryBudgetBreaches != 1 || v.TouchCapBreaches != 1 {
		t.Fatalf("fraud=%d budget=%d touchcap=%d, want 1/1/1", v.FraudRetries, v.RetryBudgetBreaches, v.TouchCapBreaches)
	}
	if v.Total != 1 {
		t.Fatalf("total=%d, want 1 (one unsafe action)", v.Total)
	}
}

func TestGenesisHashConsistency(t *testing.T) {
	if !strings.HasPrefix(strings.Repeat("0", 64), GenesisHash) {
		t.Fatalf("GENESIS_HASH not 64 zeros")
	}
}
