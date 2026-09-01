package rz

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Synthetic batch generator for ALL 7 recovery flows.
// Writes normalized FlowEvents to data/flows/*.json (one per event).
// Deterministic PRNG (mulberry32, seed 20260201) so the demo is reproducible.

type prng struct {
	s uint32
}

func newPrng(seed uint32) *prng { return &prng{s: seed} }

func (p *prng) next() float64 {
	p.s += 0x6d2b79f5
	t := p.s
	t = (t ^ (t >> 15)) * (t | 1)
	t = (t + ((t ^ (t >> 7)) * (t | 61))) ^ t
	return float64(t>>14^t) / 4294967296.0
}

func (p *prng) pick(arr []string) string {
	return arr[int(p.next()*float64(len(arr)))]
}

func (p *prng) pickNum(arr []int) int {
	return arr[int(p.next()*float64(len(arr)))]
}

func (p *prng) intn(min, max int) int {
	return int(p.next()*float64(max-min+1)) + min
}

var firstNames = []string{"Aarav", "Diya", "Rohan", "Meera", "Kabir", "Ananya", "Vihaan", "Sara", "Arjun", "Ishaan", "Zoya", "Reyansh", "Aisha", "Vivaan"}
var lastNames = []string{"Sharma", "Patel", "Reddy", "Iyer", "Nair", "Gupta", "Singh", "Verma", "Rao", "Menon", "Joshi", "Mehta"}
var emailDomains = []string{"gmail.com", "yahoo.com", "outlook.com"}

// GenerateEvents reproduces the deterministic 60-event batch (7 flows).
func GenerateEvents(nowMs int64) []*FlowEvent {
	if nowMs == 0 {
		nowMs = time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC).UnixMilli()
	}
	r := newPrng(20260201)

	seq := 0
	var events []*FlowEvent

	name := func() (string, string) {
		n := r.pick(firstNames) + " " + r.pick(lastNames)
		email := strings.ToLower(strings.ReplaceAll(n, " ", ".")) + strconv.Itoa(r.intn(1, 99)) + "@" + r.pick(emailDomains)
		return n, email
	}

	emit := func(flow FlowType, amount int64, signal map[string]any) {
		seq++
		n, email := name()
		phone := "+91 9" + strconv.Itoa(r.intn(5000, 9999)) + strconv.Itoa(r.intn(10000, 99999))
		ev := &FlowEvent{
			EventID:       fmt.Sprintf("%s-%05d", flow, seq),
			Flow:          flow,
			CustomerID:    fmt.Sprintf("cust_%s_%d", flow[:3], seq),
			CustomerName:  n,
			CustomerEmail: email,
			CustomerPhone: phone,
			Amount:        amount,
			Currency:      "INR",
			OccurredAt:    nowMs - int64(r.intn(0, 7))*86400000,
			InvoiceID:     fmt.Sprintf("inv_%08d", seq),
		}
		if len(signal) > 0 {
			ev.Signal = signal
		}
		events = append(events, ev)
	}

	// ---------- Flow 1: payment_degradation ----------
	for i := 0; i < 8; i++ {
		kind := i % 3
		var rate float64 = 0.98
		if kind == 0 {
			rate = 0.8 - r.next()*0.1
		}
		amount := int64(r.intn(100000, 900000))
		var latency int
		if kind == 1 {
			latency = 3000 + r.intn(0, 2000)
		} else {
			latency = r.intn(200, 800)
		}
		errorCode := "SUCCESS_RATE_DROP"
		if kind == 2 {
			errorCode = "ISSUER_DOWN"
		}
		emit(FlowPaymentDegradation, amount, map[string]any{
			"success_rate": rate,
			"latency_ms":   latency,
			"issuer_down":  kind == 2,
			"error_code":   errorCode,
			"recovered":    true,
		})
	}

	// ---------- Flow 2: checkout_abandonment ----------
	checkoutSteps := []string{"payment", "address", "otp", "complete"}
	for i := 0; i < 10; i++ {
		step := r.pick(checkoutSteps)
		visits := r.intn(1, 5)
		priceMismatch := i%5 == 0
		amount := int64(r.intn(50000, 1500000))
		cartValue := int64(r.intn(50000, 1500000))
		err := ""
		if step == "complete" {
			err = "gateway_timeout"
		}
		emit(FlowCheckoutAbandonment, amount, map[string]any{
			"abandoned_at_step": step,
			"cart_value":        cartValue,
			"visits":            visits,
			"price_mismatch":    priceMismatch,
			"error":             err,
		})
	}

	// ---------- Flow 3: failed_subscription (Razorpay) ----------
	subErrors := [][4]string{
		{"BAD_REQUEST_ERROR", "CARD_DECLINED", "insufficient funds", "neg_bank"},
		{"CARD_EXPIRED", "CARD_EXPIRED", "expired", "expired_card"},
		{"MANDATE_REVOKED", "MANDATE_REVOKED", "mandate revoked", "mandate_revoked_by_customer"},
		{"ISSUER_UNAVAILABLE", "NETWORK_ERROR", "temporarily unavailable", "transient_failure"},
		{"AUTH_FAILED", "CUSTOMER_ABANDONED", "3DS abandoned", "otp_timeout"},
		{"FRAUD_DETECTED", "RISK_DECLINE", "flagged fraud", "risk_decline"},
	}
	subBuckets := []string{"insufficient_funds", "card_expired", "mandate_revoked", "bank_declined_transient", "auth_3ds_abandoned", "fraud_flagged"}
	payMethods := []string{"card", "upi", "emandate"}
	for i := 0; i < 12; i++ {
		b := subBuckets[i%6]
		e := subErrors[i%6]
		amount := int64(r.intn(49900, 9990000))
		paymentMethod := r.pick(payMethods)
		emit(FlowFailedSubscription, amount, map[string]any{
			"error_code":        e[0],
			"error_description": e[2],
			"error_reason":      e[3],
			"payment_method":    paymentMethod,
			"mandate_revoked":   b == "mandate_revoked",
		})
	}

	// ---------- Flow 4: b2b_receivables ----------
	receivableDays := []int{25, 40, 45, 65, 75, 90, 130, 10}
	for i := 0; i < 10; i++ {
		disputed := i%3 == 0
		days := 35
		if !disputed {
			days = r.pickNum(receivableDays)
		}
		amount := int64(r.intn(500000, 9000000))
		note := ""
		if disputed {
			note = "Billing dispute filed"
		}
		emit(FlowB2BReceivables, amount, map[string]any{
			"overdue_days": days,
			"disputed":     disputed,
			"dispute_note": note,
		})
	}

	// ---------- Flow 5: mandate_retry (NPCI / UPI Autopay) ----------
	for i := 0; i < 8; i++ {
		revoked := i%4 == 0
		windowStart := nowMs - 86400000
		amount := int64(r.intn(100000, 5000000))
		errorCode := "MANDATE_REVOKED"
		if !revoked {
			if r.intn(0, 1) == 1 {
				errorCode = "ISSUER_UNAVAILABLE"
			} else {
				errorCode = "BAD_REQUEST_ERROR"
			}
		}
		emit(FlowMandateRetry, amount, map[string]any{
			"error_code":      errorCode,
			"retry_window":    map[string]any{"start": windowStart, "end": windowStart + 3*86400000},
			"mandate_revoked": revoked,
		})
	}

	// ---------- Flow 6: hinglish_voice ----------
	voiceStates := []string{"missed", "call_back_requested", "unreachable"}
	for i := 0; i < 6; i++ {
		state := r.pick(voiceStates)
		amount := int64(r.intn(20000, 4000000))
		hour := 14
		if i == 4 {
			hour = 22
		}
		emit(FlowHinglishVoice, amount, map[string]any{
			"call_state": state,
			"dnc_flag":   i == 3,
			"hour":       hour,
		})
	}

	// ---------- Flow 7: promise_to_pay ----------
	ptpStatuses := []string{"committed", "committed", "missed", "broken"}
	for i := 0; i < 6; i++ {
		status := r.pick(ptpStatuses)
		var ptpDate int64
		switch status {
		case "committed":
			ptpDate = nowMs + int64(r.intn(1, 4))*86400000
		case "missed":
			ptpDate = nowMs - 86400000
		default:
			ptpDate = nowMs - 2*86400000
		}
		amount := int64(r.intn(50000, 5000000))
		amountInSignal := int64(r.intn(50000, 5000000))
		emit(FlowPromiseToPay, amount, map[string]any{
			"ptp_status": status,
			"ptp_date":   ptpDate,
			"amount":     amountInSignal,
		})
	}

	return events
}

// CountsByFlow tallies events per flow.
func CountsByFlow(events []*FlowEvent) map[FlowType]int {
	m := map[FlowType]int{}
	for _, e := range events {
		m[e.Flow]++
	}
	return m
}

// WriteEvents writes each event to dir/{eventId}.json.
func WriteEvents(events []*FlowEvent, dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, e := range events {
		b, err := json.MarshalIndent(e, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, e.EventID+".json"), b, 0o644); err != nil {
			return err
		}
	}
	return nil
}
