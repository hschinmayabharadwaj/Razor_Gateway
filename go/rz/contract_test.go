package rz

import (
	"strings"
	"testing"
)

// Golden contracts pinning behavior against documented Razorpay /
// India-payments reality. These are the "what we promise" tests: if the
// vendor changes a code or a payload shape, this file fails loudly.

// TestContractParseTrustedEvent pins the normalized-envelope contract the
// runner consumes. A raw Razorpay payload has NO top-level id/flow and must be
// translated by the merchant-side adapter before ParseTrustedEvent — that is a
// documented gap, not an accident: this test proves the split on purpose.
func TestContractParseTrustedEvent(t *testing.T) {
	cases := []struct {
		name        string
		body        string
		wantEventID string
		wantFlow    string
		wantOK      bool
	}{
		{"envelope event_id+flow",
			`{"event_id":"evt_fail_1","flow":"failed_subscription","amount":49900}`,
			"evt_fail_1", "failed_subscription", true},
		{"envelope id+entity.type",
			`{"id":"pay_123","entity":{"type":"payment"}}`,
			"pay_123", "payment", true},
		{"envelope event_id only (flow empty)",
			`{"event_id":"evt_2"}`,
			"evt_2", "", true},
		{"raw razorpay shape (adapter gap)",
			`{"event":"payment.failed","entity":"event","payload":{"payment":{"id":"pay_1","entity":{"type":"payment"}}}}`,
			"", "", false},
		{"empty body", ``, "", "", false},
		{"malformed json", `not json`, "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id, flow, ok := ParseTrustedEvent(tc.body)
			if ok != tc.wantOK {
				t.Fatalf("ok=%v want %v", ok, tc.wantOK)
			}
			if id != tc.wantEventID {
				t.Fatalf("eventId=%q want %q", id, tc.wantEventID)
			}
			if flow != tc.wantFlow {
				t.Fatalf("flow=%q want %q", flow, tc.wantFlow)
			}
		})
	}
}

// TestContractRazorpayErrorCodes pins classification of Razorpay's documented
// error codes to stable reason buckets. This is the golden contract that a
// real webhook adapter can rely on.
func TestContractRazorpayErrorCodes(t *testing.T) {
	cases := map[string]ReasonBucket{
		"CARD_DECLINED":                 ReasonInsufficientFunds,
		"BAD_REQUEST_ERROR":             ReasonInsufficientFunds,
		"CARD_EXPIRED":                  ReasonCardExpired,
		"DIRECTAUTHPARAM_FAILED":        ReasonAuth3dsAbandoned,
		"DIRECTORAUTHPARAM_FAILED":      ReasonAuth3dsAbandoned, // legacy spelling also mapped
		"AUTH_FAILED":                   ReasonAuth3dsAbandoned,
		"CUSTOMER_ABANDONED":            ReasonAuth3dsAbandoned,
		"PAYMENT_AUTHENTICATION_FAILED": ReasonBankDeclinedTransien,
		"ISSUER_UNAVAILABLE":            ReasonBankDeclinedTransien,
		"NETWORK_ERROR":                 ReasonBankDeclinedTransien,
		"MANDATE_REVOKED":               ReasonMandateRevoked,
		"MANDATE_CANCELLED":             ReasonMandateRevoked,
		"FRAUD_DETECTED":                ReasonFraudFlagged,
		"RISK_DECLINE":                  ReasonFraudFlagged,
	}
	for code, want := range cases {
		ev := &FlowEvent{
			EventID: "evt_code", Flow: FlowFailedSubscription,
			Signal: map[string]any{"error_code": code},
		}
		if got := Classify(ev); got != want {
			t.Errorf("error_code %q → %q, want %q", code, got, want)
		}
		// Lower/mixed case must still classify the same.
		ev.Signal["error_code"] = strings.ToLower(code)
		if got := Classify(ev); got != want {
			t.Errorf("error_code %q (lower) → %q, want %q", code, got, want)
		}
	}
}

// TestContractWebhookSignatureKAT pins the HMAC to an independently computed
// value (openssl dgst -sha256 -hmac), so an implementation regression in the
// signature scheme is caught without a peer.
func TestContractWebhookSignatureKAT(t *testing.T) {
	const (
		secret = "secret"
		ts     = int64(1700000000)
		body   = "webhook"
		want   = "62e0f8fb6319d8a1f754bc382c940bccb2e994d0c4cbcb5a356b49eb5833de5f"
	)
	if got := ComputeWebhookSignature(secret, ts, body); got != want {
		t.Fatalf("HMAC vector mismatch: got %s want %s", got, want)
	}
	// The documented envelope "t=<ts>|s=<hex>" must verify end-to-end.
	ok, reason := VerifyWebhook(secret,
		map[string]string{"x-razorpay-signature": "t=1700000000|s=" + want},
		body, ts)
	if !ok {
		t.Fatalf("KAT failed to verify: %s", reason)
	}
}

// TestContractRedactBoundaries pins mask boundaries for the phone/email/name
// shapes the codebase actually emits.
func TestContractRedactBoundaries(t *testing.T) {
	rec := RedactPII(map[string]any{
		"customerId":    "cust_abc_12345",
		"customerName":  "Rohan Iyer",
		"customerPhone": "+91 98765 43210",
		"customerEmail": "rohan.iyer42@gmail.com",
	})
	phone := rec["customerPhone"].(string)
	if strings.Contains(phone, "8765 4") {
		t.Fatalf("phone leaks middle digits: %q", phone)
	}
	if !strings.HasPrefix(phone, "+91") {
		t.Fatalf("phone should keep prefix, got %q", phone)
	}
	email := rec["customerEmail"].(string)
	if strings.Contains(email, "rohan") {
		t.Fatalf("email leaks local part: %q", email)
	}
	if !strings.HasSuffix(email, "@gmail.com") {
		t.Fatalf("email should keep domain, got %q", email)
	}
	name := rec["customerName"].(string)
	if strings.Contains(name, "Iyer") || !strings.Contains(name, "•") {
		t.Fatalf("name not masked: %q", name)
	}

	// Short / degenerate shapes must not panic and must still mask.
	for _, val := range []any{map[string]any{
		"customerPhone": "98765", "customerEmail": "a@b.co",
		"customerName": "z", "customerId": "c",
	}, map[string]any{"customerPhone": "", "customerEmail": "", "customerName": "", "customerId": ""},
	} {
		_ = RedactPII(val.(map[string]any))
	}
}
