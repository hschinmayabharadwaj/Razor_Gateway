# Revenue Recovery Agent (multi-flow) — Go port

An AI agent that **detects revenue at risk, determines the right intervention,
and executes a bounded recovery workflow** across 7 recovery flows —
from payment failures and checkout abandonment to overdue receivables.

Recovery is a **state machine**, not a chatbot. Every money-moving / stopping
decision is made by **named policy rules** (`policy_engine`) — never by an LLM.
The only LLM seam is generating human-readable customer copy **after** a
decision has already been made.

This repository is a **from-scratch Go port** of the original TypeScript
implementation, preserving architecture, behavior, and outputs exactly
(deterministic 60-event batch, hash-chained audit log, tuning sandbox, risk
prescore, security stack). A single package `rz` (one file per module) plus
8 command-line drivers under `cmd/`.

**Why this exists (60-second pitch).** Revenue leaks across payment failures,
checkout drops, failed subscriptions, overdue receivables, UPI mandate failures,
and missed calls — not in one clean step. Razorpay's own **Vulcan** foundation
model proves pattern-based payment intelligence is where the industry is headed,
but it is closed, proprietary, and locked to their rails (no checkpoint, no
third-party API, no dataset). This project is the **auditable, merchant-portable,
compliance-first version of that same idea, for the recovery layer** — a
deterministic engine whose stopping decisions and every audit entry are provable,
measured, and hash-chained, not self-reported. The naive-vs-real comparison and
live tamper demo below make that the story a judge can see in under a minute.

## The 7 flows

| Flow | Detects | Intervenes with |
|------|---------|-----------------|
| `payment_degradation` | success-rate drop / latency spike / issuer down | degrade alert → gateway re-routing → escalate |
| `checkout_abandonment` | dropped cart/checkout step | reminder + cart incentive (cost-aware) |
| `failed_subscription` | `subscription.charged.failed` | retry budget → escalate / suppress |
| `b2b_receivables` | overdue invoice (net30/net60) | tiered dunning, dispute hold |
| `mandate_retry` | UPI Autopay / e-NACH failure | NPCI retry-window sequencing |
| `hinglish_voice` | missed call / callback / unreachable | Hinglish voice call (TRAI quiet-hours + DNC aware) |
| `promise_to_pay` | committed / missed / broken PTP | suppress until date, remind 24h before, follow up |

## Architecture

The Go port lives in `go/` as a single package `rz` (module `razor_gateway/go`),
with one file per original TS module:

```
go/
  cmd/
    gen-events        # generate the deterministic 60-event batch -> data/flows/*.json
    run-batch         # full batch run -> audit log + metrics + table + exceptions
    verify-audit      # verify the tamper-evident hash chain
    compare-policy    # REAL vs NAIVE policy comparison + compliance lift
    prescore          # prevention layer: predict-before-fail report
    sandbox           # tunable sweep backtester + locked-rule invariant
    security          # security posture demo (webhook/auth/redaction/anchor/LLM/secrets)
    demo              # walkthroughs: mandate_revoked, NPCI window, checkout incentive
  rz/
    types.go          # unified domain: FlowType, states, narrowed taxonomy, audit schema
    generate.go       # deterministic PRNG (mulberry32, seed 20260201) -> 60 events
    classify.go       # classify(event)->reason_bucket per flow (no LLM)
    rules.go          # NAMED stopping rules (pure, unit-tested; tunable vs locked)
    engines.go        # pure per-flow decision functions
    statemachine.go   # pure state transition + audit entry
    execution.go      # execute the decided action (retry / contact / voice / incentive)
    copy.go           # LLM copy seam (ONLY post-decision text generation)
    store.go          # append-only JSONL audit log (auto hash-chains)
    chain.go          # sha256 hash-chain primitives + verifyChain
    naive.go          # deliberately-naive baseline (no safety rules)
    compare.go        # REAL vs NAIVE + compliance violation counting
    config.go         # TUNABLE vs LOCKED rule separation
    sandbox.go        # tunable sweep backtester + locked-rule invariant
    riskscore.go      # pure multi-factor predictor (named factors, no black box)
    prescore.go       # retroactive predict-before-fail report + audit emission
    webhook.go        # HMAC-SHA256 webhook signature verification (Razorpay scheme)
    auth.go           # access control (deny-by-default role matrix)
    redact.go         # PII redaction for log / exception read surfaces
    anchor.go         # external append-only anchor for the hash chain
    llm.go            # LLM output validation (customer-facing seam)
    secrets.go        # env-only, fail-closed secrets (never committed)
    metrics.go        # metrics computed FROM the audit log
    table.go          # audit-log table + metrics view
    runner.go         # unified orchestrator (per-customer touch caps)
  rz/*_test.go        # 6 test suites, 71 tests
```

## Stopping rules (all named + unit tested first)

- `MAX_RETRY_ATTEMPTS = 3` per invoice — `atMaxRetryAttempts()`
- `fraud_flagged` -> suppress immediately — `fraud_suppress`
- `mandate_revoked` -> escalate to human, never retry — `mandate_revoked_escalate`
- active promise-to-pay date -> suppress all touches until it passes — `promise_to_pay_suppress` / `ptp_suppress`
- 3 failed retries -> escalate, no infinite loop — `exhaust_attempts_escalate`
- Max 3 outbound touches per customer (per-customer across the batch) — `atTouchCap()`
- **Mandate retry window** (NPCI): bounded sequencing, not "retry every 3 days" — `mandate_retry_window` / `mandate_retry_seq`
- **Checkout spam guard**: only repeat visitors, no discount on junk carts — `repeat_visitor_only` / `cart_incentive`
- **B2B dunning ladder**: net30 remind → net60 collections → legal; disputes held — `receivable_*` / `dispute_hold`
- **Voice regulatory**: TRAI quiet hours (21:00–09:00 IST) + DNC honored — `voice_do_not_call`
- **PTP compliance**: large PTPs need human supervisor sign-off — `ptp_missed_escalate`
- Batch capacity cap via single constant — `MAX_BATCH_ATTEMPTS`

Every transition writes `{event_id, timestamp, flow, reason_bucket, rule_fired,
decision, actor, outcome}` to the append-only audit log. The log is also a
**tamper-evident hash chain** (see below).

## Tamper-evident audit log (hash chain)

Each audit entry carries two extra fields (`prevHash`, `hash`) added on top of
the existing schema — no existing field is changed.

- `prevHash` = the `hash` of the immediately preceding entry (`GENESIS_HASH =
  "0"*64` for the first).
- `hash` = `sha256(prevHash + stable_stringify(entry minus hash fields))`.
  Keys are sorted before stringify so the hash reproduces exactly.

Pure functions in `go/rz/chain.go`:
- `AppendAuditEntry(log, newEntryData)` — pure append (no mutation).
- `VerifyChain(log)` — recomputes every hash and returns the first broken index.

```bash
go run ./cmd/run-batch     # writes a hash-chained audit log
go run ./cmd/verify-audit  # ✓ chain verified, N entries, no tampering detected
```

**Demo trick:** run the batch, `verify-audit` passes. Edit one line of
`go/data/audit.log.jsonl` (e.g. flip a `decision`), re-run `verify-audit` — it
prints `✗ chain broken at entry N`.

## Naive-policy baseline & compliance lift

`go/rz/` runs the REAL policy engine and a deliberately-NAIVE one over the
IDENTICAL 60-event batch, and measures the compliance lift:

- `naive.go` — a baseline with NO safety rules: blindly retries every failure
  every 3 days up to 10 attempts regardless of reason bucket (including
  `fraud_flagged` and `mandate_revoked`), no touch cap, no DNC/quiet-hours check,
  no PTP suppression.
- `compare.go` — runs both, then re-checks **every naive action against the real
  rule predicates** (`isFraudFlagged`, `isMandateRevoked`, `isDoNotCall`,
  `atTouchCap`, `atMaxRetryAttempts`, `hasActivePromiseToPay`) and counts the
  exact violations the naive policy would commit. Nothing is hand-waved.

```bash
go run ./cmd/compare-policy
```

Outputs a table + a data-computed one-line takeaway, e.g.:
*"Naive retry recovers 87.7% vs 61.5% (+26.3pp) but commits 65 compliance
violations (20 fraud retries, 40 mandate revoke retries, 42 touch-cap breaches,
42 retry-budget breaches, 4 PTP breaches) ... — violations our policy engine
structurally cannot make."*

## Constraints honored

- **No LLM call ever makes a retry/stop/escalate decision.** LLM (`llm_copy`) is
  used only for: (a) generating customer copy, (b) summarizing the exception list.
- Every money-moving action traces to a **named rule**, not "the model decided."
- Recovery metrics are **computed from the audit log**, not asserted.

## Prevention layer: risk prescore (predict-before-fail)

The recovery layer is, by definition, reacting after a leak. This module is the
bridge to becoming a **risk manager** instead of a cleanup crew.

`go/rz/riskscore.go` scores every customer BEFORE the attempt using **named,
inspectable factors** — `prior_decline_count_90d`, `mandate_age_days`,
`days_since_last_decline`, `prior_chargeback_count_90d`, `card_expiry_within_60d`.
No black box: each factor contributes visible points, sum → `low|medium|high`.

`go/rz/prescore.go` runs that score **retroactively over the same batch** and
compares pre-score against the ACTUAL outcome (drawn from the verified audit
log), then emits each prescore as a hash-chained audit entry (zero schema change).

```bash
go run ./cmd/prescore
```

Output (computed, not claimed):
*"25 of 28 events that were not auto-recovered (89% recall) had already been
flagged high-risk BEFORE the attempt (49% precision)."*

This is the same thesis as **Razorpay's Vulcan** (pattern-based payment
intelligence at massive scale) — but transparent (named factors vs. undisclosed
"3,000 signals"), merchant-portable (a pure function over your own data, not
locked to Razorpay's rails), and compliance-native (the prescores are themselves
hash-chained). The honest framing: *Vulcan validates the direction; ours is the
auditable, portable version of it, for the recovery layer.*

## Backtest sandbox: tunables move, LOCKED rules don't

`go/rz/config.go` separates rules into two kinds:

- **TUNABLE** — business levers (`maxRetryAttempts`, `maxTouchesPerCustomer`,
  `checkoutReminderCap`, `maxVoiceCalls`, `cartIncentiveThreshold`,
  `ptpSupervisorThreshold`, `mandateWindowDays`, `receivableTier2Days`). Raise or
  lower these; recovery/touches move with them.
- **LOCKED** — hard safety/compliance invariants (`fraud_suppress`,
  `mandate_revoked_escalate`, `voice_do_not_call`, TRAI `quiet_hours`). Their
  predicates accept NO tunable, so no configuration can disable them.

`go/rz/sandbox.go` re-runs the SAME batch under a tunable sweep:

```bash
go run ./cmd/sandbox
```

```
scenario       recovery  touches  cost/rec  locked_viol
baseline       61.5%     81       2.53/rec  0
aggressive     63.6%     83       2.44/rec  0
conservative   16.6%     43       8.60/rec  0
high_incentive 61.5%     81       2.53/rec  0
✓ Locked safety/compliance rules never budge across any tunable sweep
```

## One command runs everything

```bash
go run ./cmd/demo
```

The demo CLI runs the real batch plus walkthroughs proving correct behavior:
- **mandate_revoked** handled gracefully (refuses to retry, escalates),
- **mandate retry** sequenced within the NPCI retry window (India-specific),
- **checkout abandonment** recovered cost-aware (spam guard + incentive threshold).

`compare-policy`, `prescore`, and `sandbox` each run their own stage of the full
story as standalone CLIs (the original TS `e2e` bundled all of them together).

## Security posture (honest, tested — not claimed)

The security stack mirrors the TS original module-for-module. `go run
./cmd/security` demos each defense live, and `go test` proves them.

**Implemented & tested (`go/rz/security_test.go`, 25 cases):**
- **Webhook signature verification** (`webhook.go`) — Razorpay's `t=<ts>|s=<hmac>`
  HMAC-SHA256 scheme, plus 5-minute replay-window check. No event is trusted as
  an input until it passes this gate. Constant-time compare; signature mismatch,
  replay, and tampered-body are all rejected.
- **Access control, deny-by-default** (`auth.go`) — every privileged action
  (`run_batch`, `tune_sandbox`, `read_audit_log`, …) is gated behind a
  caller-supplied credential + a role matrix (`operator`/`admin`/`auditor`).
  Unknown credentials and missing keys are rejected before any action.
- **PII redaction** (`redact.go`) — the hash chain protects *integrity*, not
  *confidentiality*; this module masks phone/email/name/customer-id at every read
  surface (dashboard, exception list, auditor export).
- **External anchor** (`anchor.go`) — a raw chain can be silently rebuilt by
  someone with write access; this publishes a root hash to an append-only sink
  outside the log, and a rebuilt chain fails the tail/root check.
- **LLM output validation** (`llm.go`) — the LLM never decides, but its copy
  still reaches customers. Injection patterns, `<script>`/`<iframe>`, control
  chars, over-length, internal/localhost URLs, and PII leakage are rejected at the
  boundary.
- **Secrets policy** (`secrets.go`) — fail-closed `requireSecret()` from env only,
  never hard-coded, never printed (`redactSecret()`).
- **Sandbox isolation** (`execution.go`) — `ExecutionMode == 'sandbox'`
  structurally cannot call a live/test-mode charge API; charge-capable flows are
  pure in-process simulations. `/demo`, `/sandbox` all run sandboxed.

**Known gaps — stated honestly (the pitch names these before a judge does):**
- Auth is a *stub* (API-key allow-list), not a real identity/session layer.
- No rate-limiting / replay protection on retry *execution* (charge attempts).
- No DPDP data-retention/deletion story for the audit log.
- No anomaly detection watching the policy engine's own behavior.
- The webhook secret here is an injected demo value; production uses
  `requireSecret('RAZORPAY_WEBHOOK_SECRET')`.

## Commands

Build and test:

```bash
cd go
export PATH="$HOME/go-toolchain/go/bin:$PATH"   # adjust to your Go install
go build ./...
go vet ./...
go test ./...                     # 6 suites, 71 tests
```

CLIs (run from `go/` after generation):

```bash
go run ./cmd/gen-events    # generate the deterministic 60-event batch -> data/flows/
go run ./cmd/run-batch     # full batch run + metrics + audit table + exceptions
go run ./cmd/verify-audit  # verify the tamper-evident hash chain
go run ./cmd/compare-policy# REAL vs NAIVE policy comparison + compliance lift
go run ./cmd/prescore      # prevention layer: predict-before-fail report
go run ./cmd/sandbox       # tunable sweep, locked rules invariant
go run ./cmd/security      # security posture demo (webhook/auth/redaction/anchor/LLM/secrets)
go run ./cmd/demo          # batch walkthroughs (mandate_revoked, NPCI window, checkout incentive)
```

## Demo output

`go run ./cmd/run-batch` prints measured results over the 60-event batch:
- recovery rate (`recovered_amount / total_at_risk_amount`),
- cost per recovery (`touches_sent / recovered_count`),
- per-flow breakdown,
- full exception list (escalated / abandoned / waiting) with reasons and rule fired,
- an LLM exception summary for a human reviewer, and
- a hash-chain verification (`✓ chain verified: 188 entries, no tampering detected`).

Measured parity with the original TypeScript run is exact: 188 audit entries,
₹851208.52 recovered of ₹1384523.97 at risk (61.5%), 32 recovered, 81 touches,
65 naive-policy compliance violations.