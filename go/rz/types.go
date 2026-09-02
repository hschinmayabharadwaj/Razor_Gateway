// Package rz is a Go port of the TypeScript Revenue Recovery Agent.
// It preserves the original architecture: deterministic named rules, an
// audit-first hash chain, a state machine (not a chatbot), and India-specific
// recovery flows.
package rz

// FlowType identifies one of the 7 recovery flows.
type FlowType string

const (
	FlowPaymentDegradation  FlowType = "payment_degradation"
	FlowCheckoutAbandonment FlowType = "checkout_abandonment"
	FlowFailedSubscription  FlowType = "failed_subscription"
	FlowB2BReceivables      FlowType = "b2b_receivables"
	FlowMandateRetry        FlowType = "mandate_retry"
	FlowHinglishVoice       FlowType = "hinglish_voice"
	FlowPromiseToPay        FlowType = "promise_to_pay"
)

// FlowTypes is the ordered list of all flows (mirrors FLOW_TYPES).
var FlowTypes = []FlowType{
	FlowPaymentDegradation,
	FlowCheckoutAbandonment,
	FlowFailedSubscription,
	FlowB2BReceivables,
	FlowMandateRetry,
	FlowHinglishVoice,
	FlowPromiseToPay,
}

// ReasonBucket is the narrow per-flow classification taxonomy.
type ReasonBucket string

const (
	ReasonInsufficientFunds    ReasonBucket = "insufficient_funds"
	ReasonCardExpired          ReasonBucket = "card_expired"
	ReasonMandateRevoked       ReasonBucket = "mandate_revoked"
	ReasonBankDeclinedTransien ReasonBucket = "bank_declined_transient"
	ReasonAuth3dsAbandoned     ReasonBucket = "auth_3ds_abandoned"
	ReasonFraudFlagged         ReasonBucket = "fraud_flagged"
	ReasonSuccessRateDrop      ReasonBucket = "success_rate_drop"
	ReasonLatencySpike         ReasonBucket = "latency_spike"
	ReasonIssuerDown           ReasonBucket = "issuer_down"
	ReasonPriceMismatch        ReasonBucket = "price_mismatch"
	ReasonPaymentStepAbandoned ReasonBucket = "payment_step_abandoned"
	ReasonAddressAbandoned     ReasonBucket = "address_abandoned"
	ReasonSlowCheckout         ReasonBucket = "slow_checkout"
	ReasonCheckoutError        ReasonBucket = "checkout_error"
	ReasonOverdueNet30         ReasonBucket = "overdue_net30"
	ReasonOverdueNet60         ReasonBucket = "overdue_net60"
	ReasonDisputedReceivable   ReasonBucket = "disputed_receivable"
	ReasonMandateInsufficient  ReasonBucket = "mandate_insufficient"
	ReasonMandateBankDown      ReasonBucket = "mandate_bank_down"
	ReasonMandateAuthPending   ReasonBucket = "mandate_auth_pending"
	ReasonVoiceMissedCall      ReasonBucket = "voice_missed_call"
	ReasonVoiceAskedCallBack   ReasonBucket = "voice_asked_call_back"
	ReasonVoiceUnreachable     ReasonBucket = "voice_unreachable"
	ReasonPtpCommitted         ReasonBucket = "ptp_committed"
	ReasonPtpMissed            ReasonBucket = "ptp_missed"
	ReasonPtpBroken            ReasonBucket = "ptp_broken"
)

// AgentState is the finite state-machine state.
type AgentState string

const (
	AgentDetected         AgentState = "detected"
	AgentDiagnosed        AgentState = "diagnosed"
	AgentRetryScheduled   AgentState = "retry_scheduled"
	AgentRetrying         AgentState = "retrying"
	AgentContactScheduled AgentState = "contact_scheduled"
	AgentContacting       AgentState = "contacting"
	AgentWaitingOnPtp     AgentState = "waiting_on_ptp"
	AgentRecovered        AgentState = "recovered"
	AgentEscalated        AgentState = "escalated"
	AgentAbandoned        AgentState = "abandoned"
	AgentSuppressed       AgentState = "suppressed"
)

// IsTerminalState reports whether the state is terminal (mirrors TERMINAL_STATES).
func IsTerminalState(s AgentState) bool {
	switch s {
	case AgentRecovered, AgentEscalated, AgentAbandoned, AgentSuppressed:
		return true
	}
	return false
}

// Actor identifies which system produced an audit entry.
type Actor string

const (
	ActorPolicyEngine Actor = "policy_engine"
	ActorLLMCopy      Actor = "llm_copy"
	ActorHuman        Actor = "human"
	ActorDialer       Actor = "dialer"
)

// RuleId is a named, individually testable decision rule.
type RuleId string

const (
	RuleNoOp                    RuleId = "no_op"
	RuleRecovered               RuleId = "recovered"
	RuleEscalateManual          RuleId = "escalate_manual"
	RuleAbandonManual           RuleId = "abandon_manual"
	RuleMaxTouchesCap           RuleId = "max_touches_cap"
	RuleMaxRetryAttempts        RuleId = "max_retry_attempts"
	RuleFraudSuppress           RuleId = "fraud_suppress"
	RuleMandateRevokedEsc       RuleId = "mandate_revoked_escalate"
	RulePromiseToPaySuppress    RuleId = "promise_to_pay_suppress"
	RuleScheduleRetry           RuleId = "schedule_retry"
	RuleExecuteRetry            RuleId = "execute_retry"
	RuleTransientRetry          RuleId = "transient_retry"
	RuleExhaustAttemptsEscalate RuleId = "exhaust_attempts_escalate"
	RuleMandateRetryWindow      RuleId = "mandate_retry_window"
	RuleMandateRetrySeq         RuleId = "mandate_retry_seq"
	RuleCheckoutReminder        RuleId = "checkout_reminder"
	RuleCartIncentive           RuleId = "cart_incentive"
	RuleCheckoutRecover         RuleId = "checkout_recover"
	RuleCheckoutAbandon         RuleId = "checkout_abandon"
	RuleRepeatVisitorOnly       RuleId = "repeat_visitor_only"
	RuleReceivableTier          RuleId = "receivable_tier"
	RuleInvoiceReminder         RuleId = "invoice_reminder"
	RuleInvoiceEscalateDun      RuleId = "invoice_escalate_dunning"
	RuleDisputeHold             RuleId = "dispute_hold"
	RuleDegradationAlert        RuleId = "degradation_alert"
	RuleDegradationRecover      RuleId = "degradation_recover"
	RuleDegradationEscalate     RuleId = "degradation_escalate"
	RuleVoiceCall               RuleId = "voice_call"
	RuleVoiceRetry              RuleId = "voice_retry"
	RuleVoiceEscalateHuman      RuleId = "voice_escalate_human"
	RuleVoiceDoNotCall          RuleId = "voice_do_not_call"
	RulePtpSchedule             RuleId = "ptp_schedule"
	RulePtpSuppress             RuleId = "ptp_suppress"
	RulePtpFollowup             RuleId = "ptp_followup"
	RulePtpReminderBefore       RuleId = "ptp_reminder_before"
	RulePtpMissedEscalate       RuleId = "ptp_missed_escalate"
	RuleQuietHours              RuleId = "quiet_hours"
	RuleBatchMaxAttempts        RuleId = "batch_max_attempts"
	RuleDuplicateSuppress       RuleId = "duplicate_suppress"
)

// Decision is the engine's chosen action.
type Decision string

const (
	DecisionRetry    Decision = "retry"
	DecisionContact  Decision = "contact"
	DecisionRecover  Decision = "recover"
	DecisionEscalate Decision = "escalate"
	DecisionSuppress Decision = "suppress"
	DecisionAbandon  Decision = "abandon"
	DecisionHold     Decision = "hold"
	DecisionNone     Decision = "none"
)

// AuditEntry is one row of the append-only, tamper-evident audit log.
type AuditEntry struct {
	EventID      string       `json:"eventId"`
	Timestamp    string       `json:"timestamp"`
	Flow         FlowType     `json:"flow"`
	ReasonBucket ReasonBucket `json:"reasonBucket"`
	RuleFired    RuleId       `json:"ruleFired"`
	Decision     Decision     `json:"decision"`
	Actor        Actor        `json:"actor"`
	Outcome      string       `json:"outcome"`
	State        AgentState   `json:"state"`
	Attempt      *int         `json:"attempt,omitempty"`
	Amount       *int64       `json:"amount,omitempty"`
	Currency     string       `json:"currency,omitempty"`
	InvoiceID    string       `json:"invoiceId,omitempty"`
	CustomerID   string       `json:"customerId,omitempty"`
	Channel      string       `json:"channel,omitempty"`
	Notes        string       `json:"notes,omitempty"`
	// Tamper-evidence hash chain (appended additively).
	PrevHash string `json:"prevHash,omitempty"`
	Hash     string `json:"hash,omitempty"`
}

// FlowEvent is a normalized event any flow can consume.
type FlowEvent struct {
	EventID        string         `json:"eventId"`
	Flow           FlowType       `json:"flow"`
	CustomerID     string         `json:"customerId"`
	CustomerName   string         `json:"customerName"`
	CustomerPhone  string         `json:"customerPhone,omitempty"`
	CustomerEmail  string         `json:"customerEmail,omitempty"`
	Amount         int64          `json:"amount"`
	Currency       string         `json:"currency"`
	OccurredAt     int64          `json:"occurredAt"`
	SubscriptionID string         `json:"subscriptionId,omitempty"`
	InvoiceID      string         `json:"invoiceId,omitempty"`
	OrderID        string         `json:"orderId,omitempty"`
	PlanID         string         `json:"planId,omitempty"`
	Signal         map[string]any `json:"signal,omitempty"`
}

// TouchResult mirrors the execution-layer touch outcome.
type TouchResult struct {
	Success          bool
	Channel          string
	Detail           string
	StoppedByDnc     bool
	IncentiveApplied bool
}

// RetryWindow is the NPCI / UPI Autopay retry window.
type RetryWindow struct {
	Start int64
	End   int64
}

// RecoveryContext is the input to the decision state machine.
type RecoveryContext struct {
	EventID                string
	Flow                   FlowType
	CustomerID             string
	InvoiceID              string
	Amount                 int64
	Currency               string
	Reason                 ReasonBucket
	Attempt                int
	TouchesForCustomer     int
	ActivePromiseToPayDate *int64
	OverdueDays            int
	Now                    int64
	RetryWindow            *RetryWindow
	PtpSupervisor          bool
	DNCFlag                bool
	CartValue              int64
	Visits                 int
	RollingSuccessRate     float64
}

// EvaluatedStep is the state-machine transition result.
type EvaluatedStep struct {
	State     AgentState
	RuleFired RuleId
	Decision  Decision
	Outcome   string
	RetryAt   *int64
	Channel   string
	Incentive string
	Hold      bool
}

func intp(i int) *int     { return &i }
func i64p(i int64) *int64 { return &i }
