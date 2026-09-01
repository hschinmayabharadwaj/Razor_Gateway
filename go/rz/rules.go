package rz

import (
	"time"
)

// NAMED STOPPING RULES across all flows. Every rule is a small, pure,
// individually testable function. The decision engines compose these; no LLM
// ever runs them. Money-moving / stopping decisions are always traceable to one
// of these named functions.
//
// Tunability: business-lever caps are read from a mutable config (backtest
// sweeps). The LOCKED safety rules (fraud, mandate_revoked, DNC, quiet-hours)
// accept no tunable and can never be disabled.

// Current tunable values (mutable for backtests). Defaults == shipped constants.
var tunables = DefaultTunables()

func SetTunables(t TunableConfig) TunableConfig {
	tunables = t
	return tunables
}

func SetTunableField(apply func(*TunableConfig)) TunableConfig {
	t := tunables
	apply(&t)
	tunables = t
	return tunables
}

func ResetTunables() TunableConfig {
	tunables = DefaultTunables()
	return tunables
}

func GetTunables() TunableConfig {
	return tunables
}

// ---------- Generic blast-radius caps ----------
func MaxTouchesPerCustomer() int { return tunables.MaxTouchesPerCustomer }

func MaxOutboundTouchesPerCustomer() int { return tunables.MaxTouchesPerCustomer }

func AtTouchCap(existingTouches int) bool {
	return existingTouches >= tunables.MaxTouchesPerCustomer
}

// ---------- failed_subscription / mandate_retry: retry budget ----------
func MaxRetryAttempts() int { return tunables.MaxRetryAttempts }

func AtMaxRetryAttempts(currentAttempt int) bool {
	return currentAttempt >= tunables.MaxRetryAttempts
}

func ExhaustedRetries(currentAttempt int) bool {
	return currentAttempt >= tunables.MaxRetryAttempts
}

// IsFraudFlagged never retries fraud_flagged.
func IsFraudFlagged(reason ReasonBucket) bool {
	return reason == ReasonFraudFlagged
}

// IsMandateRevoked never retries mandate_revoked -> escalate.
func IsMandateRevoked(reason ReasonBucket) bool {
	return reason == ReasonMandateRevoked
}

// HasActivePromiseToPay suppresses touches while a promise date is in the future.
func HasActivePromiseToPay(activePromiseToPayDate *int64, now int64) bool {
	if activePromiseToPayDate == nil {
		return false
	}
	return *activePromiseToPayDate > now
}

// Retryable buckets for failed_subscription.
func IsRetryable(reason ReasonBucket) bool {
	switch reason {
	case ReasonInsufficientFunds, ReasonCardExpired, ReasonBankDeclinedTransien, ReasonAuth3dsAbandoned:
		return true
	}
	return false
}

func MaxBatchAttempts() int { return 60 * tunables.MaxRetryAttempts }

// ---------- mandate_retry: NPCI / UPI Autopay retry-window constraints ----------
func MandateRetrySequenceMs() []int64 {
	days := tunables.MandateWindowDays
	if days < 1 {
		days = 1
	}
	seq := make([]int64, 0, days)
	seq = append(seq, 0) // attempt 0: on due date
	for d := 1; d < days; d++ {
		seq = append(seq, int64(d)*24*3600*1000)
	}
	return seq
}

func IsWithinMandateRetryWindow(now int64, window *RetryWindow) bool {
	if window == nil {
		return false
	}
	return now >= window.Start && now <= window.End
}

func MandateRetryAttemptAllowed(currentAttempt int, now int64, window *RetryWindow) bool {
	if window == nil {
		return false
	}
	dayOffset := int((now - window.Start) / (24 * 3600 * 1000))
	seq := MandateRetrySequenceMs()
	return dayOffset >= 0 && dayOffset < len(seq) && currentAttempt <= dayOffset
}

// ---------- checkout_abandonment ----------
const CheckoutReminderMs = 30 * 60 * 1000 // 30 min

func CheckoutAbandonReminders() int { return tunables.CheckoutReminderCap }

func AtCheckoutReminderCap(remindersSent int) bool {
	return remindersSent >= tunables.CheckoutReminderCap
}

// IsRepeatVisitor only recovers checkout for repeat / did-not-quite-finish visitors.
func IsRepeatVisitor(visits int) bool {
	if visits == 0 {
		visits = 1
	}
	return visits >= 2
}

func CartIncentiveThreshold() int64 { return tunables.CartIncentiveThreshold }

func CartEligibleForIncentive(cartValue int64) bool {
	return cartValue >= tunables.CartIncentiveThreshold
}

// ---------- b2b_receivables ----------
const ReceivableTier1Days = 30 // net30

func ReceivableTier(overdueDays int) int {
	t2 := tunables.ReceivableTier2Days
	if overdueDays < ReceivableTier1Days {
		return 0
	}
	if overdueDays < t2 {
		return 1
	}
	if overdueDays < t2*2 {
		return 2
	}
	return 3
}

func ReceivableAction(tier int) string {
	switch tier {
	case 0:
		return "none"
	case 1:
		return "remind"
	case 2:
		return "smtp"
	default:
		return "dunning"
	}
}

func IsDisputed(reason ReasonBucket) bool {
	return reason == ReasonDisputedReceivable
}

// ---------- payment_degradation ----------
const (
	DegradationSuccessRateThreshold = 0.85 // < 85% triggers alert
	DegradationLatencyMsThreshold   = 2000
)

func SuccessRateBelowThreshold(rollingRate float64) bool {
	return rollingRate < DegradationSuccessRateThreshold
}

// ---------- hinglish_voice ----------
func MaxVoiceCalls() int { return tunables.MaxVoiceCalls }

func AtVoiceCallCap(callsMade int) bool {
	return callsMade >= tunables.MaxVoiceCalls
}

// IsDoNotCall checks the DNC flag and TRAI quiet hours (21:00-09:00 IST),
// computed in IST deterministically regardless of machine timezone.
func IsDoNotCall(dncFlag bool, now int64) bool {
	if dncFlag {
		return true
	}
	if now == 0 {
		return false
	}
	istMs := now + int64(5.5*3600*1000)
	hour := time.UnixMilli(istMs).UTC().Hour()
	return hour >= 21 || hour < 9
}

// ---------- promise_to_pay ----------
const PtpReminderBeforeMs = 24 * 3600 * 1000 // remind 24h before

func PtpReminderDue(now int64, ptpDate int64) bool {
	return now >= ptpDate-PtpReminderBeforeMs && now < ptpDate
}

func PtpDateNotYet(now int64, ptpDate int64) bool {
	return now < ptpDate
}

func PtpMissed(now int64, ptpDate int64) bool {
	return now > ptpDate
}

func PtpNeedsSupervisor(amount int64) bool {
	return amount >= tunables.PtpSupervisorThreshold
}

// StoppingInput is the shared decision input.
type StoppingInput struct {
	Reason                 ReasonBucket
	CurrentAttempt         int
	TouchesForCustomer     int
	ActivePromiseToPayDate *int64
	OverdueDays            int
	Now                    int64
	RetryWindow            *RetryWindow
	DNCFlag                bool
	CartValue              int64
	Visits                 int
	RollingSuccessRate     float64
	Amount                 int64
}

func effectiveNow(now int64) int64 {
	if now == 0 {
		return time.Now().UnixMilli()
	}
	return now
}
