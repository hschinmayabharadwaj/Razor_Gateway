package rz

import (
	"time"
)

// NAIVE POLICY ENGINE — deliberately unsafe baseline.
// Has NO safety rules: retries every failure blindly up to 10 attempts on a
// fixed 3-day cadence, regardless of reason bucket (including fraud_flagged
// and mandate_revoked), with no touch cap, no DNC/quiet-hours check, and no
// PTP suppression.

const (
	NaiveMaxAttempts = 10 // blind, up to 10 attempts
	NaiveCadenceDays = 3  // retry every 3 days
)

// NaiveTouch is every touch the naive policy proposes, captured so real rules
// can re-check it.
type NaiveTouch struct {
	EventID                string
	Flow                   FlowType
	CustomerID             string
	Reason                 ReasonBucket
	Attempt                int
	TouchesForCustomer     int
	Channel                string
	Now                    int64
	DNCFlag                bool
	ActivePromiseToPayDate *int64
}

type NaiveRun struct {
	AuditEntries []AuditEntry
	Touches      []NaiveTouch
}

type NaiveOpts struct {
	Now int64
}

// NaiveShouldAct blindly acts (retry/contact) regardless of reason, up to 10.
func NaiveShouldAct(attempt int) bool { return attempt < NaiveMaxAttempts }

// RunNaiveBatch drives the naive policy over the same batch.
func RunNaiveBatch(events []*FlowEvent, audit *AuditStore, opts NaiveOpts) (NaiveRun, error) {
	nowBase := opts.Now
	if nowBase == 0 {
		nowBase = time.Now().UnixMilli()
	}
	var touches []NaiveTouch

	for _, event := range events {
		reason := Classify(event)
		s := event.Signal
		if s == nil {
			s = map[string]any{}
		}
		dncFlag := boolField(s, "dnc_flag")
		var activePromiseToPayDate *int64
		if v, ok := s["ptp_date"]; ok && v != nil {
			if n, ok2 := toInt64(v); ok2 {
				activePromiseToPayDate = &n
			}
		}

		attempt := 0
		state := AgentDetected

		for NaiveShouldAct(attempt) && state != AgentRecovered {
			touchAt := nowBase + int64(attempt)*NaiveCadenceDays*86400000 // 3-day cadence
			touchesForCustomer := 0
			for _, t := range touches {
				if t.CustomerID == event.CustomerID {
					touchesForCustomer++
				}
			}

			channel := "api"
			if event.Flow == FlowHinglishVoice {
				channel = "voice"
			}
			touches = append(touches, NaiveTouch{
				EventID:                event.EventID,
				Flow:                   event.Flow,
				CustomerID:             event.CustomerID,
				Reason:                 reason,
				Attempt:                attempt,
				TouchesForCustomer:     touchesForCustomer,
				Channel:                channel,
				Now:                    touchAt,
				DNCFlag:                dncFlag,
				ActivePromiseToPayDate: activePromiseToPayDate,
			})

			res := ExecuteAction(event, event.Flow, reason, attempt, ModeSandbox)
			decision := DecisionRetry
			if res.Recovered {
				state = AgentRecovered
				decision = DecisionRecover
			} else {
				state = AgentRetrying
			}
			detail := res.Detail
			if detail == "" {
				detail = "Blind retry attempt " + itoa(attempt+1)
			}
			actionEntry := AuditEntry{
				EventID:      event.EventID,
				Timestamp:    Iso(touchAt),
				Flow:         event.Flow,
				ReasonBucket: reason,
				RuleFired:    RuleScheduleRetry,
				Decision:     decision,
				Actor:        ActorPolicyEngine,
				Outcome:      detail,
				State:        state,
				Attempt:      intp(attempt),
				Amount:       i64p(event.Amount),
				Currency:     event.Currency,
				InvoiceID:    event.InvoiceID,
				CustomerID:   event.CustomerID,
				Channel:      res.Channel,
				Notes:        "naive_policy",
			}
			if err := audit.Append(actionEntry); err != nil {
				return NaiveRun{}, err
			}
			attempt++

			if res.Recovered {
				recEntry := actionEntry
				recEntry.RuleFired = RuleRecovered
				recEntry.Decision = DecisionRecover
				recEntry.State = AgentRecovered
				recAmt := float64(0)
				if res.RecoveredAmount > 0 {
					recAmt = float64(res.RecoveredAmount)
				}
				recEntry.Outcome = "Recovered " + formatJS(recAmt/100) + " " + event.Currency
				recEntry.Notes = "naive_policy"
				if err := audit.Append(recEntry); err != nil {
					return NaiveRun{}, err
				}
				state = AgentRecovered
			}
		}

		// Naive policy never suppresses/escalates on mandate/fraud: it just spends
		// the whole blind budget. Park as abandoned (budget exhausted, no recovery).
		if state != AgentRecovered {
			if err := audit.Append(AuditEntry{
				EventID:      event.EventID,
				Timestamp:    Iso(nowBase),
				Flow:         event.Flow,
				ReasonBucket: reason,
				RuleFired:    RuleNoOp,
				Decision:     DecisionAbandon,
				Actor:        ActorPolicyEngine,
				Outcome:      "Naive policy exhausted " + itoa(attempt) + "/" + itoa(NaiveMaxAttempts) + " blind attempts without recovery",
				State:        AgentAbandoned,
				Attempt:      intp(attempt),
				Amount:       i64p(event.Amount),
				Currency:     event.Currency,
				InvoiceID:    event.InvoiceID,
				CustomerID:   event.CustomerID,
				Notes:        "naive_policy",
			}); err != nil {
				return NaiveRun{}, err
			}
		}
	}

	all, err := audit.All()
	if err != nil {
		return NaiveRun{}, err
	}
	return NaiveRun{AuditEntries: all, Touches: touches}, nil
}
