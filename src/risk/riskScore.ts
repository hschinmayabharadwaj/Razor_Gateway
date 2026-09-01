// Prevention layer: deterministic, named-factor risk scoring.
// Mirrors the idea behind Razorpay's Vulcan (pattern-based payment
// intelligence) but is: transparent (named, inspectable factors with an audit
// trail), merchant-portable (pure function over your own data), and
// compliance-native. No black box — a judge can read every factor.

export type RiskDecision = 'low' | 'medium' | 'high';

export interface RiskFactor {
  key: string; // stable, nameable factor id
  label: string;
  value: number; // raw value
  contribution: number; // weighted points added to score
}

export interface RiskInput {
  // Customer payment/transaction history (derivable from your own data).
  history: CustomerHistory;
  // Optional current-event signal (error code, payment method, etc.).
}

export interface CustomerHistory {
  priorDeclineCount90d: number; // # declines in the last 90 days
  mandateAgeDays: number; // age of the mandate/subscription in days
  daysSinceLastDecline: number; // days since the most recent decline
  priorChargebackCount90d: number; // chargebacks in last 90 days
  cardExpiresWithinDays?: number; // days until card expiry (null = unknown)
  renewalCount?: number; // how many renewals already succeeded
  amountInRupees?: number; // current attempt amount
}

export interface RiskScore {
  score: number; // 0..100
  decision: RiskDecision;
  factors: RiskFactor[];
}

export const RISK_THRESHOLD_HIGH = 60;
export const RISK_THRESHOLD_MEDIUM = 35;

const clampTo100 = (n: number): number => Math.max(0, Math.min(100, n));

// Each factor is a small, named, inspectable contribution.
export function computeRiskFactors(h: CustomerHistory): RiskFactor[] {
  const factors: RiskFactor[] = [];

  // (a) Prior declines in 90d: each decline raises risk (capped at 3 for max).
  const declineContribution = Math.min(3, Math.max(0, h.priorDeclineCount90d)) * 20;
  factors.push({
    key: 'prior_decline_count_90d',
    label: 'Prior declines (90d)',
    value: h.priorDeclineCount90d,
    contribution: declineContribution,
  });

  // (b) Mandate age: brand-new mandate (<30d) is higher risk for autopay.
  const mandateAge = h.mandateAgeDays;
  const mandateContribution = mandateAge < 30 ? 15 : mandateAge < 90 ? 5 : 0;
  factors.push({
    key: 'mandate_age_days',
    label: 'Mandate age (days)',
    value: mandateAge,
    contribution: mandateContribution,
  });

  // (c) Recency of last decline: more recent = elevated risk.
  const recency = h.daysSinceLastDecline;
  const recencyContribution =
    recency < 3 ? 20 : recency < 14 ? 12 : recency < 30 ? 5 : 0;
  factors.push({
    key: 'days_since_last_decline',
    label: 'Days since last decline',
    value: recency,
    contribution: recencyContribution,
  });

  // (d) Chargebacks: strong fraud/risk signal.
  const chargebackContribution = Math.min(3, Math.max(0, h.priorChargebackCount90d)) * 25;
  factors.push({
    key: 'prior_chargeback_count_90d',
    label: 'Prior chargebacks (90d)',
    value: h.priorChargebackCount90d,
    contribution: chargebackContribution,
  });

  // (e) Card expiring soon: high risk of card_expired bucket.
  if (h.cardExpiresWithinDays != null && h.cardExpiresWithinDays <= 60) {
    factors.push({
      key: 'card_expiry_within_60d',
      label: 'Card expires within 60d',
      value: h.cardExpiresWithinDays,
      contribution: 18,
    });
  }

  return factors;
}

export function riskScore(input: RiskInput): RiskScore {
  const factors = computeRiskFactors(input.history);
  const score = factors.reduce((s, f) => s + f.contribution, 0);
  const decision: RiskDecision =
    score >= RISK_THRESHOLD_HIGH ? 'high' : score >= RISK_THRESHOLD_MEDIUM ? 'medium' : 'low';
  const topFactors = [...factors].sort((a, b) => b.contribution - a.contribution).filter((f) => f.contribution > 0);
  return { score: clampTo100(score), decision, factors: topFactors };
}

// A named decision the recovery layer can act on preemptively.
export function isHighRisk(r: RiskScore): boolean {
  return r.decision === 'high';
}
