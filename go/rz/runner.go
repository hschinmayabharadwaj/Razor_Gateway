package rz

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Unified batch orchestrator. Drives every FlowEvent through the decision
// engine / state machine, executes the decided action, generates LLM copy only
// after a decision, and appends every transition to the audit log.
// The engine decides; this loop only executes and logs.

type Escape struct {
	EventID string
	Subject string
	Flow    FlowType
}

type BatchResult struct {
	AuditEntries         []AuditEntry
	Escapes              []Escape
	ExceptionSummary     string
	BatchAttemptLimitHit bool
}

type RunnerOpts struct {
	Now              int64
	MaxBatchAttempts *int
}

// RunBatch runs the whole batch into the audit store.
func RunBatch(events []*FlowEvent, audit *AuditStore, opts RunnerOpts) (BatchResult, error) {
	batchAttemptLimitHit := false
	maxBatch := MaxBatchAttempts()
	if opts.MaxBatchAttempts != nil {
		maxBatch = *opts.MaxBatchAttempts
	}
	used := 0

	touchesByCustomer := map[string]int{}
	escapes := []Escape{}
	escalatedEvents := []AuditEntry{}
	escalatedIDs := map[string]bool{}
	now := opts.Now

	for _, event := range events {
		// Idempotency gate: a duplicate eventId must never re-execute or
		// re-touch. Claim is atomic (serialized by the store mutex) and survives
		// restarts because it is hydrated from the existing log, so concurrent
		// or replayed webhook deliveries are at-most-once.
		firstSeen, err := audit.Claim(event.EventID)
		if err != nil {
			return BatchResult{}, err
		}
		if !firstSeen {
			dup := AuditEntry{
				EventID:      event.EventID,
				Timestamp:    Iso(now),
				Flow:         event.Flow,
				ReasonBucket: Classify(event),
				RuleFired:    RuleDuplicateSuppress,
				Decision:     DecisionSuppress,
				Actor:        ActorPolicyEngine,
				Outcome:      "Duplicate eventId already processed; suppressed by idempotency gate (at-most-once)",
				State:        AgentSuppressed,
				CustomerID:   event.CustomerID,
				InvoiceID:    event.InvoiceID,
				Amount:       i64p(event.Amount),
				Currency:     event.Currency,
			}
			if err := audit.Append(dup); err != nil {
				return BatchResult{}, err
			}
			continue
		}

		if used >= maxBatch {
			batchAttemptLimitHit = true
			break
		}

		reason := Classify(event)

		ctxBase := RecoveryContext{
			EventID:    event.EventID,
			Flow:       event.Flow,
			CustomerID: event.CustomerID,
			InvoiceID:  event.InvoiceID,
			Amount:     event.Amount,
			Currency:   event.Currency,
			Reason:     reason,
			Now:        now,
		}

		attempt := 0
		state := AgentState(AgentDetected)
		guard := 0

		for !runningTerminal(state) && guard < 100 {
			guard++
			if used >= maxBatch {
				batchAttemptLimitHit = true
				break
			}
			used++

			ctx := flowContext(event, ctxBase, attempt, touchesByCustomer)
			sr, err := StepState(ctx)
			if err != nil {
				return BatchResult{}, err
			}
			next, entry := sr.Next, sr.Audit
			if err := audit.Append(entry); err != nil {
				return BatchResult{}, err
			}
			state = next.State

			switch next.Decision {
			case DecisionRetry, DecisionContact:
				res := ExecuteAction(event, event.Flow, reason, attempt, ModeSandbox)
				touchesByCustomer[event.CustomerID]++
				actionEntry := entry
				actionEntry.RuleFired = RuleRecovered
				actionEntry.Decision = DecisionRecover
				if !res.Recovered {
					actionEntry.RuleFired = entry.RuleFired
					actionEntry.Decision = entry.Decision
				}
				actionEntry.State = AgentRecovered
				switch {
				case res.Recovered:
					actionEntry.State = AgentRecovered
				case entry.State == AgentContactScheduled:
					actionEntry.State = AgentContacting
				default:
					actionEntry.State = AgentRetrying
				}
				actionEntry.Channel = res.Channel
				actionEntry.Outcome = res.Detail
				actionEntry.Actor = ActorPolicyEngine
				actionEntry.Attempt = intp(attempt)
				actionEntry.Notes = res.Note
				if err := audit.Append(actionEntry); err != nil {
					return BatchResult{}, err
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
					if err := audit.Append(recEntry); err != nil {
						return BatchResult{}, err
					}
					state = AgentRecovered
				}
			case DecisionEscalate:
				copy := GenerateCopy(CopyInput{
					EventID:        event.EventID,
					Flow:           event.Flow,
					CustomerName:   event.CustomerName,
					CustomerEmail:  event.CustomerEmail,
					AmountInRupees: float64(event.Amount) / 100,
					Reason:         reason,
					InvoiceID:      event.InvoiceID,
					OverdueDays:    int(numField(event.Signal, "overdue_days")),
				})
				llmEntry := entry
				llmEntry.RuleFired = RuleNoOp
				llmEntry.Decision = DecisionEscalate
				llmEntry.Actor = ActorLLMCopy
				llmEntry.State = AgentEscalated
				llmEntry.Outcome = "Generated " + copy.Channel + " message: " + copy.Subject
				if err := audit.Append(llmEntry); err != nil {
					return BatchResult{}, err
				}
				escapes = append(escapes, Escape{EventID: event.EventID, Subject: copy.Subject, Flow: event.Flow})
				if !escalatedIDs[event.EventID] {
					escalatedIDs[event.EventID] = true
					escalatedEvents = append(escalatedEvents, entry)
				}
				state = AgentEscalated
			case DecisionHold:
				holdEntry := entry
				holdEntry.RuleFired = entry.RuleFired
				holdEntry.Decision = DecisionHold
				holdEntry.Actor = ActorPolicyEngine
				holdEntry.State = AgentWaitingOnPtp
				holdEntry.Outcome = "Held " + event.EventID + " (" + string(entry.RuleFired) + ") pending next scheduled window"
				if err := audit.Append(holdEntry); err != nil {
					return BatchResult{}, err
				}
				state = AgentWaitingOnPtp
			case DecisionNone:
				noneEntry := entry
				noneEntry.RuleFired = entry.RuleFired
				noneEntry.Decision = DecisionNone
				noneEntry.Actor = ActorPolicyEngine
				noneEntry.State = AgentAbandoned
				noneEntry.Outcome = "No recovery action warranted for " + event.EventID + " (" + string(entry.RuleFired) + ")"
				if err := audit.Append(noneEntry); err != nil {
					return BatchResult{}, err
				}
				state = AgentAbandoned
			default:
				// suppress / abandon / recover / none: terminal-ish; loop guard exits
			}
		}
	}

	exInput := make([]ExceptionInput, 0, len(escalatedEvents))
	for _, e := range escalatedEvents {
		amt := float64(0)
		if e.Amount != nil {
			amt = float64(*e.Amount)
		}
		exInput = append(exInput, ExceptionInput{
			EventID:        e.EventID,
			Flow:           e.Flow,
			Reason:         e.ReasonBucket,
			AmountInRupees: amt / 100,
		})
	}
	allEntries, err := audit.All()
	if err != nil {
		return BatchResult{}, err
	}
	return BatchResult{
		AuditEntries:         allEntries,
		Escapes:              escapes,
		ExceptionSummary:     GenerateExceptionSummary(exInput).Text,
		BatchAttemptLimitHit: batchAttemptLimitHit,
	}, nil
}

func flowContext(event *FlowEvent, base RecoveryContext, attempt int, touchesByCustomer map[string]int) *RecoveryContext {
	s := event.Signal
	if s == nil {
		s = map[string]any{}
	}
	ctx := base
	ctx.Attempt = attempt
	ctx.TouchesForCustomer = touchesByCustomer[event.CustomerID]
	if v, ok := s["ptp_date"]; ok && v != nil {
		if n, ok2 := toInt64(v); ok2 {
			ctx.ActivePromiseToPayDate = &n
		}
	}
	ctx.OverdueDays = int(numField(s, "overdue_days"))
	if rw, ok := s["retry_window"].(map[string]any); ok {
		start, okS := toInt64(rw["start"])
		end, okE := toInt64(rw["end"])
		if okS && okE {
			w := &RetryWindow{Start: start, End: end}
			ctx.RetryWindow = w
		}
	}
	ctx.DNCFlag = boolField(s, "dnc_flag")
	ctx.CartValue = int64(numField(s, "cart_value"))
	ctx.Visits = int(numField(s, "visits"))
	ctx.RollingSuccessRate = numField(s, "success_rate")
	return &ctx
}

func toInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case int:
		return int64(n), true
	case int64:
		return n, true
	case float32:
		return int64(n), true
	}
	return 0, false
}

func runningTerminal(s AgentState) bool {
	switch s {
	case AgentRecovered, AgentEscalated, AgentAbandoned, AgentSuppressed, AgentWaitingOnPtp:
		return true
	}
	return false
}

// LoadEvents reads all normalized flow events from a directory (*.json), sorted
// by filename for cross-platform determinism.
func LoadEvents(dir string) ([]*FlowEvent, error) {
	if dir == "" {
		dir = filepath.Join("data", "flows")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, ent := range entries {
		if !ent.IsDir() && strings.HasSuffix(ent.Name(), ".json") {
			names = append(names, ent.Name())
		}
	}
	sort.Strings(names)
	var events []*FlowEvent
	for _, n := range names {
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			return nil, err
		}
		var e FlowEvent
		if err := json.Unmarshal(b, &e); err != nil {
			return nil, err
		}
		events = append(events, &e)
	}
	return events, nil
}
