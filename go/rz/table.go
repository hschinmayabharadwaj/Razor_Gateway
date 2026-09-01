package rz

import (
	"fmt"
	"strings"
)

// Plain-text functional dashboard rendered from the audit log.

// RenderTable builds the table view of the audit log.
func RenderTable(log []AuditEntry) string {
	terminal := map[string]AuditEntry{}
	lifecycle := map[string][]string{}
	var order []string
	for _, e := range log {
		arr := lifecycle[e.EventID]
		arr = append(arr, symbol(e.State)+" "+string(e.Decision)+"("+string(e.RuleFired)+"/"+string(e.Actor)+")")
		lifecycle[e.EventID] = arr
		if IsTerminalState(e.State) {
			if _, ok := terminal[e.EventID]; !ok {
				order = append(order, e.EventID)
			}
			terminal[e.EventID] = e
		}
	}

	header := []string{"event_id", "flow", "reason", "INR", "touches", "lifecycle"}
	rows := make([][]string, 0, len(order))
	for _, id := range order {
		e := terminal[id]
		touches := 0
		for _, s := range lifecycle[id] {
			if strings.Contains(s, ":retry") || strings.Contains(s, ":contact") {
				touches++
			}
		}
		amt := float64(0)
		if e.Amount != nil {
			amt = float64(*e.Amount) / 100
		}
		rows = append(rows, []string{
			id,
			string(e.Flow),
			string(e.ReasonBucket),
			fmt.Sprintf("%.0f", amt),
			fmt.Sprintf("%d", touches),
			strings.Join(lifecycle[id], " > "),
		})
	}
	return renderGrid(header, rows)
}

// RenderMetrics builds the metrics dashboard.
func RenderMetrics(m Metrics) string {
	var out []string
	out = append(out, "")
	out = append(out, "===== METRICS (computed from audit log) =====")
	out = append(out, "Total at-risk:       ₹"+fmt.Sprintf("%.2f", m.TotalAtRiskRupees))
	out = append(out, "Recovered:           ₹"+fmt.Sprintf("%.2f", m.RecoveredRupees))
	out = append(out, "Recovery rate:       "+fmt.Sprintf("%.1f", m.RecoveryRate*100)+"%")
	out = append(out, "Touches sent:        "+fmt.Sprintf("%d", m.TouchesSent))
	out = append(out, "Recovered count:     "+fmt.Sprintf("%d", m.RecoveredCount))
	out = append(out, "Cost per recovery:   "+fmt.Sprintf("%.2f", m.CostPerRecovery)+" touches/recovery")
	out = append(out, "Escalated:           "+fmt.Sprintf("%d", m.EscalatedCount))
	out = append(out, "Abandoned:           "+fmt.Sprintf("%d", m.AbandonedCount))
	out = append(out, "Suppressed:          "+fmt.Sprintf("%d", m.SuppressedCount))
	out = append(out, "")
	out = append(out, "===== BREAKDOWN BY FLOW =====")
	h := []string{"flow", "events", "recovered", "recovered(INR)", "esc", "sup", "abn", "touches"}
	r := make([][]string, 0, len(FlowTypes))
	for _, f := range FlowTypes {
		d := m.ByFlow[f]
		r = append(r, []string{
			string(f),
			fmt.Sprintf("%d", d.Events),
			fmt.Sprintf("%d", d.RecoveredCount),
			fmt.Sprintf("%.0f", d.RecoveredRupees),
			fmt.Sprintf("%d", d.Escalated),
			fmt.Sprintf("%d", d.Suppressed),
			fmt.Sprintf("%d", d.Abandoned),
			fmt.Sprintf("%d", d.Touches),
		})
	}
	out = append(out, renderGrid(h, r))
	out = append(out, "")
	out = append(out, "===== EXCEPTION LIST (escalated / abandoned / waiting_on_ptp) =====")
	if len(m.ExceptionList) == 0 {
		out = append(out, "  (none)")
	} else {
		eh := []string{"event_id", "flow", "customer", "invoice", "reason", "status", "INR", "rule"}
		er := make([][]string, 0, len(m.ExceptionList))
		for _, e := range m.ExceptionList {
			er = append(er, []string{
				e.EventID, string(e.Flow), e.CustomerID, e.InvoiceID, string(e.Reason), e.Status,
				fmt.Sprintf("%.0f", e.AmountInRupees), e.RuleFired,
			})
		}
		out = append(out, renderGrid(eh, er))
	}
	return strings.Join(out, "\n")
}

func symbol(s AgentState) string {
	switch s {
	case AgentRecovered:
		return "R"
	case AgentEscalated:
		return "E"
	case AgentAbandoned:
		return "A"
	case AgentSuppressed:
		return "S"
	case AgentRetryScheduled:
		return "s"
	case AgentRetrying:
		return "r"
	case AgentContactScheduled:
		return "c"
	case AgentContacting:
		return "C"
	case AgentWaitingOnPtp:
		return "P"
	case AgentDiagnosed:
		return "d"
	default:
		return "?"
	}
}

func renderGrid(header []string, rows [][]string) string {
	widths := make([]int, len(header))
	for i, hh := range header {
		widths[i] = runeLen(hh)
	}
	for _, rr := range rows {
		for i, cell := range rr {
			l := runeLen(cell)
			if l > widths[i] {
				widths[i] = l
			}
		}
	}
	line := func(cells []string) string {
		parts := make([]string, len(cells))
		for i, c := range cells {
			parts[i] = padEnd(c, widths[i])
		}
		return strings.Join(parts, "  ")
	}
	sep := make([]string, len(header))
	for i := range header {
		sep[i] = strings.Repeat("-", widths[i])
	}
	out := []string{line(header), strings.Join(sep, "  ")}
	for _, rr := range rows {
		out = append(out, line(rr))
	}
	return strings.Join(out, "\n")
}

func runeLen(s string) int {
	n := 0
	for range s {
		n++
	}
	return n
}

func padEnd(s string, w int) string {
	if runeLen(s) >= w {
		return s
	}
	return s + strings.Repeat(" ", w-runeLen(s))
}
