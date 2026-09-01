package rz

// Execution layer: for each flow, execute the bounded recovery action decided
// by the policy engine. Returns touch/recovery results. No decision is made
// here — this only runs what the engine already decided.

// ExecutionMode controls whether a money-moving "charge" interaction is
// simulated or could reach a live provider. SAFETY INVARIANT: the sandbox /
// backtest path MUST always run in 'sandbox' mode, where charge execution is a
// pure, in-process simulation that can never call a real Razorpay charge API.
// 'live' is reserved for production and requires an explicit authenticated
// call site (see security).
type ExecutionMode string

const (
	ModeSandbox ExecutionMode = "sandbox"
	ModeLive    ExecutionMode = "live"
)

// SandboxGuarantee is the exported guarantee statement (TS: SANDBOX_GUARANTEE).
const SandboxGuarantee = "Sandbox/backtest mode never calls a live or test-mode charge API — " +
	"charge interactions in sandbox are pure in-process simulations."

// Deterministic seeded PRNG so the demo/replays are stable per event+attempt.
func SeededRandom(seedStr string, salt int) float64 {
	seed := 0
	for _, ch := range seedStr {
		seed += int(ch)
	}
	seed += salt * 9973
	// JS: (seed * 2654435761) >>> 0
	v := uint32(int64(seed) * 2654435761)
	return float64(v) / 4294967296.0
}

// ExecutionResult is the outcome of an executed recovery touch.
type ExecutionResult struct {
	Success         bool
	Channel         string
	Detail          string
	Recovered       bool
	RecoveredAmount int64
	DNcBlocked      bool
	Note            string
}

// ExecuteAction performs the simulated recovery touch per flow/channel.
func ExecuteAction(event *FlowEvent, flow FlowType, reason ReasonBucket, attempt int, mode ExecutionMode) ExecutionResult {
	if mode == ModeSandbox {
		switch flow {
		case FlowFailedSubscription, FlowMandateRetry:
			return executeRetryCharge(event, reason, attempt)
		case FlowCheckoutAbandonment:
			return executeCheckoutTouch(event, reason, attempt)
		case FlowB2BReceivables:
			return executeReceivableTouch(event, reason, attempt)
		case FlowPaymentDegradation:
			return executeDegradation(tryDec(event))
		case FlowHinglishVoice:
			return executeVoiceCall(event, reason, attempt)
		case FlowPromiseToPay:
			return executePtpFollowUp(event, reason, attempt)
		}
	}
	// Live mode: would delegate to a real, authenticated provider adapter. That
	// adapter is intentionally not wired in this repo; the seam is explicit.
	switch flow {
	case FlowFailedSubscription, FlowMandateRetry:
		return executeRetryCharge(event, reason, attempt)
	case FlowCheckoutAbandonment:
		return executeCheckoutTouch(event, reason, attempt)
	case FlowB2BReceivables:
		return executeReceivableTouch(event, reason, attempt)
	case FlowPaymentDegradation:
		return executeDegradation(tryDec(event))
	case FlowHinglishVoice:
		return executeVoiceCall(event, reason, attempt)
	case FlowPromiseToPay:
		return executePtpFollowUp(event, reason, attempt)
	}
	panic("unhandled flow " + string(flow))
}

func executeRetryCharge(event *FlowEvent, reason ReasonBucket, attempt int) ExecutionResult {
	id := event.EventID
	r := SeededRandom(id, attempt)
	prob := 0.0
	switch reason {
	case ReasonBankDeclinedTransien:
		prob = 0.7
	case ReasonMandateInsufficient, ReasonInsufficientFunds:
		prob = 0.5
	case ReasonCardExpired:
		prob = 0.35
	case ReasonMandateBankDown:
		prob = 0.6
	case ReasonMandateAuthPending, ReasonAuth3dsAbandoned:
		prob = 0.3
	default:
		prob = 0.0 // never retried
	}
	success := r < prob
	payID := "pay_retry_" + id + "_" + itoa(attempt)
	detail := "Retry attempt " + itoa(attempt+1) + " failed (" + string(reason) + ")"
	if success {
		detail = "Retry attempt " + itoa(attempt+1) + " succeeded (" + payID + ")"
	}
	amt := int64(0)
	if success {
		amt = event.Amount
	}
	return ExecutionResult{
		Success:         success,
		Channel:         "api",
		Recovered:       success,
		RecoveredAmount: amt,
		Detail:          detail,
	}
}

func executeCheckoutTouch(event *FlowEvent, _ ReasonBucket, attempt int) ExecutionResult {
	channel := "whatsapp"
	if attempt == 0 {
		channel = "email"
	}
	r := SeededRandom(event.EventID, attempt)
	success := r < 0.4 // ~40% of abandoned carts recovered via reminder
	detail := "Checkout reminder sent (" + channel + "), no recovery yet"
	if success {
		suffix := ""
		if attempt == 0 {
			suffix = " (incentive applied)"
		}
		detail = "Recovered abandoned cart " + event.EventID + " via " + channel + suffix
	}
	amt := int64(0)
	if success {
		amt = event.Amount
	}
	return ExecutionResult{
		Success:         true,
		Channel:         channel,
		Recovered:       success,
		RecoveredAmount: amt,
		Detail:          detail,
	}
}

func executeReceivableTouch(event *FlowEvent, _ ReasonBucket, attempt int) ExecutionResult {
	channel := "sms"
	switch attempt {
	case 0:
		channel = "email"
	case 1:
		channel = "whatsapp"
	}
	r := SeededRandom(event.EventID, attempt)
	success := r < 0.35
	detail := "Dunning touch sent for " + event.EventID + " (" + channel + ")"
	if success {
		detail = "B2B receivable " + event.EventID + " collected via " + channel
	}
	amt := int64(0)
	if success {
		amt = event.Amount
	}
	return ExecutionResult{
		Success:         true,
		Channel:         channel,
		Recovered:       success,
		RecoveredAmount: amt,
		Detail:          detail,
	}
}

func executeDegradation(recover *bool) ExecutionResult {
	rec := recover != nil && *recover
	detail := "Degradation detected; alert triggered"
	if rec {
		detail = "Degradation window cleared; success rate back above threshold"
	}
	return ExecutionResult{
		Success:         true,
		Channel:         "api",
		Recovered:       rec,
		RecoveredAmount: 0,
		Detail:          detail,
	}
}

func executeVoiceCall(event *FlowEvent, _ ReasonBucket, attempt int) ExecutionResult {
	r := SeededRandom(event.EventID, attempt)
	answered := r < 0.5
	if !answered {
		return ExecutionResult{Success: false, Channel: "voice", Detail: "Missed call / no answer", Note: "retry once more"}
	}
	recovered := r < 0.3
	if recovered {
		return ExecutionResult{Success: true, Channel: "voice", Recovered: true, RecoveredAmount: event.Amount, Detail: "Hinglish voice call converted (customer paid)"}
	}
	return ExecutionResult{Success: true, Channel: "voice", Recovered: false, RecoveredAmount: 0, Detail: "Hinglish voice call answered; customer requested callback"}
}

func executePtpFollowUp(event *FlowEvent, _ ReasonBucket, attempt int) ExecutionResult {
	r := SeededRandom(event.EventID, attempt)
	recovered := r < 0.5
	if recovered {
		return ExecutionResult{Success: true, Channel: "email", Recovered: true, RecoveredAmount: event.Amount, Detail: "Promise-to-pay honored after follow-up"}
	}
	return ExecutionResult{Success: true, Channel: "email", Recovered: false, RecoveredAmount: 0, Detail: "Promise-to-pay reminder sent, awaiting payment"}
}

func tryDec(event *FlowEvent) *bool {
	// payment_degradation: recovered if event carries a success signal
	v, ok := event.Signal["recovered"]
	if !ok {
		return nil
	}
	if b, ok := v.(bool); ok {
		return &b
	}
	return nil
}
