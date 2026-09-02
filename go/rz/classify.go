package rz

import (
	"strings"
)

// Deterministic classification per flow. Each flow maps its raw signal/error
// code onto ONE narrow reason bucket. Pure functions, no LLM.

var paymentBuckets = []ReasonBucket{
	ReasonInsufficientFunds,
	ReasonCardExpired,
	ReasonMandateRevoked,
	ReasonBankDeclinedTransien,
	ReasonAuth3dsAbandoned,
	ReasonFraudFlagged,
}

// Razorpay error-code map (shared by subscription + mandate + payment flows).
var razorpayErrorCodes = map[string]ReasonBucket{
	"BAD_REQUEST_ERROR":             ReasonInsufficientFunds,
	"CARD_DECLINED":                 ReasonInsufficientFunds,
	"CARD_EXPIRED":                  ReasonCardExpired,
	"CARD_EXPIRED_CODE":             ReasonCardExpired,
	"DIRECTORAUTHPARAM_FAILED":      ReasonAuth3dsAbandoned,
	"ISSUER_UNAVAILABLE":            ReasonBankDeclinedTransien,
	"UNAUTHORIZED_PAYMENT":          ReasonBankDeclinedTransien,
	"PAYMENT_AUTHENTICATION_FAILED": ReasonBankDeclinedTransien,
	"BANK_REFUND_DECLINED":          ReasonBankDeclinedTransien,
	"NETWORK_ERROR":                 ReasonBankDeclinedTransien,
	"MANDATE_REVOKED":               ReasonMandateRevoked,
	"MANDATE_INVALID":               ReasonMandateRevoked,
	"MANDATE_CANCELLED":             ReasonMandateRevoked,
	"FRAUD_DETECTED":                ReasonFraudFlagged,
	"RISK_DECLINE":                  ReasonFraudFlagged,
	"AUTH_FAILED":                   ReasonAuth3dsAbandoned,
	"DIRECTAUTHPARAM_FAILED":        ReasonAuth3dsAbandoned, // canonical Razorpay code
	"CUSTOMER_ABANDONED":            ReasonAuth3dsAbandoned,
	"AUTH_ACCEPTED_LATER":           ReasonAuth3dsAbandoned,
	"SUCCESS_RATE_DROP":             ReasonSuccessRateDrop,
	"LATENCY_SPIKE":                 ReasonLatencySpike,
	"ISSUER_DOWN":                   ReasonIssuerDown,
}

// strField reads a string field from a signal map.
func strField(s map[string]any, key string) string {
	v, ok := s[key]
	if !ok || v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func numField(s map[string]any, key string) float64 {
	v, ok := s[key]
	if !ok || v == nil {
		return 0
	}
	switch n := v.(type) {
	case float64:
		return n
	case float32:
		return float64(n)
	case int:
		return float64(n)
	case int64:
		return float64(n)
	case int32:
		return float64(n)
	case uint64:
		return float64(n)
	}
	return 0
}

func boolField(s map[string]any, key string) bool {
	v, ok := s[key]
	if !ok || v == nil {
		return false
	}
	if b, ok := v.(bool); ok {
		return b
	}
	return false
}

func pickBucketFromCode(code string) (ReasonBucket, bool) {
	if code == "" {
		return "", false
	}
	b, ok := razorpayErrorCodes[strings.ToUpper(code)]
	return b, ok
}

// ClassifySubscription is Flow 3: failed subscription / mandate retry.
func ClassifySubscription(signal map[string]any) ReasonBucket {
	if code, ok := pickBucketFromCode(strField(signal, "error_code")); ok {
		return code
	}
	desc := strings.ToLower(strField(signal, "error_description") + " " + strField(signal, "error_reason"))
	switch {
	case strings.Contains(desc, "insufficient") || strings.Contains(desc, "limit"):
		return ReasonInsufficientFunds
	case strings.Contains(desc, "expired"):
		return ReasonCardExpired
	case strings.Contains(desc, "mandate") && (strings.Contains(desc, "revoke") || strings.Contains(desc, "cancel") || strings.Contains(desc, "invalid")):
		return ReasonMandateRevoked
	case strings.Contains(desc, "fraud") || strings.Contains(desc, "risk") || strings.Contains(desc, "suspicious"):
		return ReasonFraudFlagged
	case strings.Contains(desc, "abandoned") || strings.Contains(desc, "3ds") || strings.Contains(desc, "auth"):
		return ReasonAuth3dsAbandoned
	default:
		return ReasonBankDeclinedTransien
	}
}

// ClassifyCheckout is Flow 2: checkout abandonment.
func ClassifyCheckout(signal map[string]any) ReasonBucket {
	step := strField(signal, "abandoned_at_step")
	err := strField(signal, "error")
	if err != "" {
		return ReasonCheckoutError
	}
	if strings.Contains(step, "payment") || strings.Contains(step, "otp") || strings.Contains(step, "upi") {
		return ReasonPaymentStepAbandoned
	}
	if strings.Contains(step, "address") {
		return ReasonAddressAbandoned
	}
	if numField(signal, "page_load_ms") > 5000 {
		return ReasonSlowCheckout
	}
	if boolField(signal, "price_mismatch") {
		return ReasonPriceMismatch
	}
	return ReasonPaymentStepAbandoned
}

// ClassifyReceivable is Flow 4: B2B receivables.
func ClassifyReceivable(signal map[string]any) ReasonBucket {
	if boolField(signal, "disputed") || strField(signal, "dispute_note") != "" {
		return ReasonDisputedReceivable
	}
	overdueDays := int(numField(signal, "overdue_days"))
	if overdueDays < 60 {
		return ReasonOverdueNet30
	}
	return ReasonOverdueNet60
}

// ClassifyDegradation is Flow 1: payment degradation.
func ClassifyDegradation(signal map[string]any) ReasonBucket {
	if code, ok := pickBucketFromCode(strField(signal, "error_code")); ok {
		return code
	}
	if numField(signal, "success_rate") < 0.85 {
		return ReasonSuccessRateDrop
	}
	if numField(signal, "latency_ms") > 2000 {
		return ReasonLatencySpike
	}
	if boolField(signal, "issuer_down") {
		return ReasonIssuerDown
	}
	return ReasonBankDeclinedTransien
}

// ClassifyVoice is Flow 6: Hinglish voice.
func ClassifyVoice(signal map[string]any) ReasonBucket {
	state := strField(signal, "call_state")
	switch state {
	case "missed", "no_answer":
		return ReasonVoiceMissedCall
	case "call_back_requested":
		return ReasonVoiceAskedCallBack
	default:
		return ReasonVoiceUnreachable
	}
}

// ClassifyPromiseToPay is Flow 7: promise-to-pay tracker.
func ClassifyPromiseToPay(signal map[string]any) ReasonBucket {
	status := strField(signal, "ptp_status")
	switch status {
	case "broken":
		return ReasonPtpBroken
	case "missed":
		return ReasonPtpMissed
	default:
		return ReasonPtpCommitted
	}
}

// Classify normalizes any FlowEvent's signal into one reason bucket.
func Classify(event *FlowEvent) ReasonBucket {
	signal := event.Signal
	if signal == nil {
		signal = map[string]any{}
	}
	switch event.Flow {
	case FlowFailedSubscription, FlowMandateRetry:
		return ClassifySubscription(signal)
	case FlowCheckoutAbandonment:
		return ClassifyCheckout(signal)
	case FlowB2BReceivables:
		return ClassifyReceivable(signal)
	case FlowPaymentDegradation:
		return ClassifyDegradation(signal)
	case FlowHinglishVoice:
		return ClassifyVoice(signal)
	case FlowPromiseToPay:
		return ClassifyPromiseToPay(signal)
	}
	return ReasonBankDeclinedTransien
}
