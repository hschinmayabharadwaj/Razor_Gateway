using System.Text.Json.Serialization;

namespace GatewayUI.Models;

// ============================================================================
// Domain DTOs. These mirror the JSON emitted by the Go HTTP adapter (go/rz/
// adapter.go + streamserver.go). The backend is authoritative; these records
// only shape what the UI renders. No computation happens at this layer.
// ============================================================================

public record AuditEntryDto(
    [property: JsonPropertyName("eventId")] string? EventId,
    [property: JsonPropertyName("timestamp")] string? Timestamp,
    [property: JsonPropertyName("flow")] string? Flow,
    [property: JsonPropertyName("reasonBucket")] string? ReasonBucket,
    [property: JsonPropertyName("ruleFired")] string? RuleFired,
    [property: JsonPropertyName("decision")] string? Decision,
    [property: JsonPropertyName("actor")] string? Actor,
    [property: JsonPropertyName("outcome")] string? Outcome,
    [property: JsonPropertyName("state")] string? State,
    [property: JsonPropertyName("amount")] long? Amount,
    [property: JsonPropertyName("currency")] string? Currency,
    [property: JsonPropertyName("attempt")] int? Attempt,
    [property: JsonPropertyName("channel")] string? Channel,
    [property: JsonPropertyName("triggeredBy")] string? TriggeredBy,
    [property: JsonPropertyName("prevHash")] string? PrevHash,
    [property: JsonPropertyName("hash")] string? Hash
);

public record ChainStatusDto(
    [property: JsonPropertyName("valid")] bool Valid,
    [property: JsonPropertyName("entries")] int Entries,
    [property: JsonPropertyName("brokenAt")] int? BrokenAt
);

// ----------------------------------------------------------------------------
// SSE stream event (Go emits eventType: "audit" | "chain_status")
// ----------------------------------------------------------------------------

public abstract record StreamEvent;
public sealed record AuditStreamEvent(AuditEntryDto Entry) : StreamEvent;
public sealed record ChainStatusStreamEvent(ChainStatusDto Status) : StreamEvent;

public enum StreamPhase { Connecting, Connected, Reconnecting, Denied }
public record StreamStatus(StreamPhase Phase, string Detail);

// ----------------------------------------------------------------------------
// /metrics
// ----------------------------------------------------------------------------

public record FlowMetricsDto(
    [property: JsonPropertyName("events")] int Events,
    [property: JsonPropertyName("recoveredCount")] int RecoveredCount,
    [property: JsonPropertyName("recoveredRupees")] double RecoveredRupees,
    [property: JsonPropertyName("escalated")] int Escalated,
    [property: JsonPropertyName("suppressed")] int Suppressed,
    [property: JsonPropertyName("abandoned")] int Abandoned,
    [property: JsonPropertyName("touches")] int Touches
);

public record EligibilityDto(
    [property: JsonPropertyName("blockedByCompliance")] int BlockedByCompliance,
    [property: JsonPropertyName("eligibleEvents")] int EligibleEvents,
    [property: JsonPropertyName("eligibleRecovered")] int EligibleRecovered,
    [property: JsonPropertyName("eligibleRecoveryRate")] double EligibleRecoveryRate,
    [property: JsonPropertyName("blendedRecoveryRate")] double BlendedRecoveryRate
);

public record MetricsDto(
    [property: JsonPropertyName("totalEvents")] int TotalEvents,
    [property: JsonPropertyName("totalAtRiskRupees")] double TotalAtRiskRupees,
    [property: JsonPropertyName("recoveredCount")] int RecoveredCount,
    [property: JsonPropertyName("recoveredRupees")] double RecoveredRupees,
    [property: JsonPropertyName("recoveryRate")] double RecoveryRate,
    [property: JsonPropertyName("touchesSent")] int TouchesSent,
    [property: JsonPropertyName("costPerRecovery")] double CostPerRecovery,
    [property: JsonPropertyName("escalatedCount")] int EscalatedCount,
    [property: JsonPropertyName("abandonedCount")] int AbandonedCount,
    [property: JsonPropertyName("suppressedCount")] int SuppressedCount,
    [property: JsonPropertyName("byFlow")] Dictionary<string, FlowMetricsDto>? ByFlow,
    [property: JsonPropertyName("eligibility")] EligibilityDto? Eligibility
);

// ----------------------------------------------------------------------------
// /exceptions
// ----------------------------------------------------------------------------

public record ExceptionDto(
    [property: JsonPropertyName("eventId")] string? EventId,
    [property: JsonPropertyName("flow")] string? Flow,
    [property: JsonPropertyName("customer")] string? Customer,
    [property: JsonPropertyName("invoice")] string? Invoice,
    [property: JsonPropertyName("reason")] string? Reason,
    [property: JsonPropertyName("status")] string? Status,
    [property: JsonPropertyName("amountInRupees")] double AmountInRupees,
    [property: JsonPropertyName("ruleFired")] string? RuleFired,
    [property: JsonPropertyName("outcome")] string? Outcome
);

public record ExceptionsDto(
    [property: JsonPropertyName("exceptions")] List<ExceptionDto>? Exceptions
);

// ----------------------------------------------------------------------------
// /compare-policy
// ----------------------------------------------------------------------------

public record ViolationsDto(
    [property: JsonPropertyName("fraudRetries")] int FraudRetries,
    [property: JsonPropertyName("mandateRetries")] int MandateRetries,
    [property: JsonPropertyName("quietHourCalls")] int QuietHourCalls,
    [property: JsonPropertyName("dncBreaches")] int DNcBreaches,
    [property: JsonPropertyName("touchCapBreaches")] int TouchCapBreaches,
    [property: JsonPropertyName("retryBudgetBreaches")] int RetryBudgetBreaches,
    [property: JsonPropertyName("ptpSuppressionBreaches")] int PtpSuppressionBreaches,
    [property: JsonPropertyName("total")] int Total
);

public record PolicyComparisonDto(
    [property: JsonPropertyName("real")] MetricsDto? Real,
    [property: JsonPropertyName("naive")] MetricsDto? Naive,
    [property: JsonPropertyName("violations")] ViolationsDto? Violations,
    [property: JsonPropertyName("totalNaiveTouches")] int TotalNaiveTouches,
    [property: JsonPropertyName("takeaway")] string? Takeaway
);

// ----------------------------------------------------------------------------
// /prescore
// ----------------------------------------------------------------------------

public record PrescoreRowDto(
    [property: JsonPropertyName("eventId")] string? EventId,
    [property: JsonPropertyName("flow")] string? Flow,
    [property: JsonPropertyName("score")] int Score,
    [property: JsonPropertyName("tier")] string? Tier,
    [property: JsonPropertyName("topFactor")] string? TopFactor,
    [property: JsonPropertyName("failedToRecover")] bool FailedToRecover,
    [property: JsonPropertyName("recovered")] bool Recovered
);

public record PrescoreDto(
    [property: JsonPropertyName("rows")] List<PrescoreRowDto>? Rows,
    [property: JsonPropertyName("totalEvents")] int TotalEvents,
    [property: JsonPropertyName("failedEvents")] int FailedEvents,
    [property: JsonPropertyName("highRiskAmongFailed")] int HighRiskAmongFailed,
    [property: JsonPropertyName("highRiskTotal")] int HighRiskTotal,
    [property: JsonPropertyName("precision")] double Precision,
    [property: JsonPropertyName("recall")] double Recall,
    [property: JsonPropertyName("headline")] string? Headline
);

// ----------------------------------------------------------------------------
// /sandbox
// ----------------------------------------------------------------------------

public record LockedViolationsDto(
    [property: JsonPropertyName("fraud")] int Fraud,
    [property: JsonPropertyName("mandateRevoked")] int MandateRevoked,
    [property: JsonPropertyName("dnc")] int DNc,
    [property: JsonPropertyName("quietHours")] int QuietHours,
    [property: JsonPropertyName("total")] int Total
);

public record SandboxScenarioDto(
    [property: JsonPropertyName("label")] string? Label,
    [property: JsonPropertyName("recoveryRate")] double RecoveryRate,
    [property: JsonPropertyName("touchesSent")] int TouchesSent,
    [property: JsonPropertyName("costPerRecovery")] double CostPerRecovery,
    [property: JsonPropertyName("lockedViolations")] LockedViolationsDto? LockedViolations
);

public record SandboxDto(
    [property: JsonPropertyName("scenarios")] List<SandboxScenarioDto>? Scenarios,
    [property: JsonPropertyName("lockedInvariant")] bool LockedInvariant,
    [property: JsonPropertyName("headline")] string? Headline,
    [property: JsonPropertyName("selectedScenario")] string? SelectedScenario,
    [property: JsonPropertyName("lockedRules")] List<string>? LockedRules
);

// ----------------------------------------------------------------------------
// Admin intervention
// ----------------------------------------------------------------------------

public record AdminActionRequest(
    [property: JsonPropertyName("eventId")] string EventId,
    [property: JsonPropertyName("action")] string Action,
    [property: JsonPropertyName("channel")] string? Channel = null
);

public record AdminActionResult(
    [property: JsonPropertyName("ok")] bool Ok,
    [property: JsonPropertyName("eventId")] string? EventId,
    [property: JsonPropertyName("decision")] string? Decision,
    [property: JsonPropertyName("state")] string? State,
    [property: JsonPropertyName("outcome")] string? Outcome,
    [property: JsonPropertyName("refusedBy")] string? RefusedBy,
    [property: JsonPropertyName("refusedReason")] string? RefusedReason
);
