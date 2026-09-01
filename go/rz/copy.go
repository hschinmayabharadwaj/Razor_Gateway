package rz

import (
	"fmt"
	"strings"
)

// LLM copy generation — the ONLY allowed LLM seam.
// It NEVER decides whether to retry/stop/escalate; it only formats human-facing
// text AFTER the policy engine has decided.

type CopyInput struct {
	EventID        string
	Flow           FlowType
	CustomerName   string
	CustomerEmail  string
	AmountInRupees float64
	Reason         ReasonBucket
	InvoiceID      string
	OverdueDays    int
	Channel        string
}

type MessageCopy struct {
	Subject  string
	Body     string
	Channel  string
	Producer string
}

func subjectFor(flow FlowType, r ReasonBucket, amt float64) string {
	switch flow {
	case FlowFailedSubscription:
		return "Your renewal failed — quick fix needed"
	case FlowCheckoutAbandonment:
		return "You left something in your cart"
	case FlowB2BReceivables:
		if r == ReasonDisputedReceivable {
			return "Invoice query received"
		}
		return "Invoice #{invoice} due"
	case FlowPaymentDegradation:
		return "Payment success rate alert"
	case FlowMandateRetry:
		return "Autopay retry scheduled"
	case FlowHinglishVoice:
		return "Recovery call — aapka payment pending hai"
	case FlowPromiseToPay:
		return "Your payment promise reminder"
	}
	return ""
}

// GenerateCopy produces a templated message for ANY flow.
func GenerateCopy(input CopyInput) MessageCopy {
	ch := input.Channel
	if ch == "" {
		ch = "email"
	}
	return MessageCopy{
		Subject:  subjectFor(input.Flow, input.Reason, input.AmountInRupees),
		Body:     templatedBody(input),
		Channel:  ch,
		Producer: "llm",
	}
}

func templatedBody(input CopyInput) string {
	who := input.CustomerName
	amt := fmt.Sprintf("₹%.2f", input.AmountInRupees)
	switch input.Flow {
	case FlowHinglishVoice:
		return "Namaste " + who + "! Aapke renewal ka paisa " + amt + " pending hai. Ek baar payment kar dijiye, sab set ho jayega. Dhanyavaad!"
	case FlowCheckoutAbandonment:
		return "Hi " + who + ", you left items worth " + amt + " in your cart. Complete your order and we'll hold them for you."
	case FlowB2BReceivables:
		return "Dear " + who + ", invoice #" + input.InvoiceID + " of " + amt + " is overdue by " + itoa(input.OverdueDays) + " days. Please arrange payment."
	case FlowPaymentDegradation:
		return "Hi team, payment success rate dropped below threshold near " + input.EventID + ". Recommend reviewing the payment gateway config."
	case FlowMandateRetry:
		return "Hi " + who + ", we scheduled an autopay retry for " + amt + ". No action needed unless it fails again."
	case FlowPromiseToPay:
		return "Hi " + who + ", this is a reminder about your payment promise of " + amt + "."
	case FlowFailedSubscription:
		return "Hi " + who + ", your subscription renewal of " + amt + " could not be completed (" + string(input.Reason) + "). Please update your payment method."
	default:
		return "Hi " + who + ", your subscription renewal of " + amt + " could not be completed (" + string(input.Reason) + "). Please update your payment method."
	}
}

type ExceptionInput struct {
	EventID        string
	Flow           FlowType
	Reason         ReasonBucket
	AmountInRupees float64
}

type ExceptionSummary struct {
	Text     string
	Producer string
}

// GenerateExceptionSummary summarizes exceptions for a human reviewer.
func GenerateExceptionSummary(exceptions []ExceptionInput) ExceptionSummary {
	type kv struct {
		key string
		n   int
	}
	var ordered []kv
	counts := map[string]int{}
	for _, e := range exceptions {
		k := string(e.Flow)
		if _, ok := counts[k]; !ok {
			ordered = append(ordered, kv{key: k})
		}
		counts[k]++
	}
	for i := range ordered {
		ordered[i].n = counts[ordered[i].key]
	}
	var lines []string
	for _, o := range ordered {
		lines = append(lines, "  - "+o.key+": "+itoa(o.n))
	}
	total := 0.0
	for _, e := range exceptions {
		total += e.AmountInRupees
	}
	text := "Human Reviewer — " + itoa(len(exceptions)) + " exceptions require manual action totalling ₹" +
		fmt.Sprintf("%.2f", total) + ".\nBy flow:\n" + strings.Join(lines, "\n") +
		"\nReview each to resolve within the retry/promise window."
	return ExceptionSummary{Text: text, Producer: "llm"}
}
