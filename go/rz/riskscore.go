package rz

// Prevention layer: deterministic, named-factor risk scoring.
// Transparent (named, inspectable factors with an audit trail), merchant-
// portable (pure function over your own data), compliance-native. No black
// box — every factor is readable by a judge.

type RiskDecision string

const (
	RiskLow    RiskDecision = "low"
	RiskMedium RiskDecision = "medium"
	RiskHigh   RiskDecision = "high"
)

const (
	RISK_THRESHOLD_HIGH   = 60
	RISK_THRESHOLD_MEDIUM = 35
)

type RiskFactor struct {
	Key          string
	Label        string
	Value        float64
	Contribution float64
}

type CustomerHistory struct {
	PriorDeclineCount90d    int
	MandateAgeDays          int
	DaysSinceLastDecline    int
	PriorChargebackCount90d int
	CardExpiresWithinDays   *int
	RenewalCount            int
	AmountInRupees          float64
}

type RiskInput struct {
	History CustomerHistory
}

type RiskScore struct {
	Score    float64
	Decision RiskDecision
	Factors  []RiskFactor
}

func clampTo100(n float64) float64 {
	if n < 0 {
		return 0
	}
	if n > 100 {
		return 100
	}
	return n
}

// computeRiskFactors returns each small, named, inspectable contribution.
func computeRiskFactors(h CustomerHistory) []RiskFactor {
	var factors []RiskFactor

	declineContribution := min3float(float64(h.PriorDeclineCount90d), 3) * 20
	factors = append(factors, RiskFactor{
		Key:          "prior_decline_count_90d",
		Label:        "Prior declines (90d)",
		Value:        float64(h.PriorDeclineCount90d),
		Contribution: declineContribution,
	})

	mandateAge := h.MandateAgeDays
	mandateContribution := float64(0)
	if mandateAge < 30 {
		mandateContribution = 15
	} else if mandateAge < 90 {
		mandateContribution = 5
	}
	factors = append(factors, RiskFactor{
		Key:          "mandate_age_days",
		Label:        "Mandate age (days)",
		Value:        float64(mandateAge),
		Contribution: mandateContribution,
	})

	recency := h.DaysSinceLastDecline
	recencyContribution := float64(0)
	if recency < 3 {
		recencyContribution = 20
	} else if recency < 14 {
		recencyContribution = 12
	} else if recency < 30 {
		recencyContribution = 5
	}
	factors = append(factors, RiskFactor{
		Key:          "days_since_last_decline",
		Label:        "Days since last decline",
		Value:        float64(recency),
		Contribution: recencyContribution,
	})

	chargebackContribution := min3float(float64(h.PriorChargebackCount90d), 3) * 25
	factors = append(factors, RiskFactor{
		Key:          "prior_chargeback_count_90d",
		Label:        "Prior chargebacks (90d)",
		Value:        float64(h.PriorChargebackCount90d),
		Contribution: chargebackContribution,
	})

	if h.CardExpiresWithinDays != nil && *h.CardExpiresWithinDays <= 60 {
		factors = append(factors, RiskFactor{
			Key:          "card_expiry_within_60d",
			Label:        "Card expires within 60d",
			Value:        float64(*h.CardExpiresWithinDays),
			Contribution: 18,
		})
	}

	return factors
}

func min3float(n, cap float64) float64 {
	if n < 0 {
		return 0
	}
	if n > cap {
		return cap
	}
	return n
}

// RiskScore computes a 0..100 deterministic risk score with named factors.
// The *decision* uses the un-clamped sum, mirroring the TS threshold logic;
// the returned score clamps to 0..100. Factors with contribution 0 are dropped.
func riskScore(input RiskInput) RiskScore {
	factors := computeRiskFactors(input.History)
	sum := float64(0)
	for _, f := range factors {
		sum += f.Contribution
	}
	decision := RiskLow
	if sum >= RISK_THRESHOLD_HIGH {
		decision = RiskHigh
	} else if sum >= RISK_THRESHOLD_MEDIUM {
		decision = RiskMedium
	}

	// topFactors: sorted desc by contribution, then filtered > 0.
	top := make([]RiskFactor, 0, len(factors))
	for _, f := range factors {
		if f.Contribution > 0 {
			top = append(top, f)
		}
	}
	// insertion sort desc by contribution (stable)
	for i := 1; i < len(top); i++ {
		for j := i; j > 0 && top[j].Contribution > top[j-1].Contribution; j-- {
			top[j], top[j-1] = top[j-1], top[j]
		}
	}

	return RiskScore{Score: clampTo100(sum), Decision: decision, Factors: top}
}

// IsHighRisk reports whether the risk decision is 'high'.
func IsHighRisk(r RiskScore) bool { return r.Decision == RiskHigh }

// RiskScorePublic mirrors TS's exported riskScore signature.
func RiskScorePublic(history CustomerHistory) RiskScore {
	return riskScore(RiskInput{History: history})
}
