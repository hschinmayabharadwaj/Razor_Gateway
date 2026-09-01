package rz

// Sandbox / backtesting configuration. Two kinds of rule:
//
//	TUNABLE  — business-lever caps a merchant/operator may dial. Recovery
//	           trade-offs move with them (more retries => more recovery, more risk).
//
//	LOCKED   — hard safety/compliance invariants that MUST NOT be overridden by
//	           any tunable: fraud_flagged, mandate_revoked, do-not-call, and
//	           telecom quiet-hours. Their predicates accept NO tunable.
type TunableConfig struct {
	MaxRetryAttempts       int   // per-invoice retry budget
	MaxTouchesPerCustomer  int   // blast-radius cap on outbound touches
	CheckoutReminderCap    int   // max checkout reminders/incentives
	MaxVoiceCalls          int   // max voice call attempts
	CartIncentiveThreshold int64 // paise; min cart value to discount
	PtpSupervisorThreshold int64 // paise; PTPs at/above need human sign-off
	MandateWindowDays      int   // NPCI retry window length
	ReceivableTier2Days    int   // net60 boundary
}

// DefaultTunables mirrors today's shipped constants (see rules.go).
func DefaultTunables() TunableConfig {
	return TunableConfig{
		MaxRetryAttempts:       3,
		MaxTouchesPerCustomer:  3,
		CheckoutReminderCap:    2,
		MaxVoiceCalls:          2,
		CartIncentiveThreshold: 50000,
		PtpSupervisorThreshold: 2000000,
		MandateWindowDays:      3,
		ReceivableTier2Days:    60,
	}
}

// LockedRuleIds are permanently locked and can never be overridden.
var LockedRuleIds = []RuleId{
	RuleFraudSuppress,     // isFraudFlagged
	RuleMandateRevokedEsc, // isMandateRevoked
	RuleVoiceDoNotCall,    // isDoNotCall
	RuleQuietHours,        // TRAI 21:00-09:00 IST
}

var tunableRuleIds = []string{
	"max_retry_attempts",
	"max_touches_cap",
	"checkout_reminder_cap",
	"voice_call_cap",
	"cart_incentive_threshold",
	"ptp_supervisor_threshold",
	"mandate_retry_window",
	"receivable_tier2",
}
