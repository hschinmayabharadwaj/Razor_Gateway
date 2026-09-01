package rz

import (
	"regexp"
	"strings"
)

// LLM output validation / sanitization for the customer-facing seam.
// The LLM never makes a decision, but its output reaches customers (email /
// SMS / WhatsApp / voice script). That output is untrusted: a prompt-injected
// or malformed response could carry phishing-adjacent content, malicious /
// typo-squatted URLs, control characters, or leaked PII. This module is a
// last-line gate — reject-or-censor at the boundary before any copy is sent.

type LLMCopyInput struct {
	Subject string
	Body    string
	Channel string
}

type LLMValidationResult struct {
	OK      bool
	Reasons []string
	Subject string
	Body    string
}

var injectionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bignore (all )?previous instructions\b`),
	regexp.MustCompile(`(?i)\bignore (the )?above\b`),
	regexp.MustCompile(`(?i)\bsystem prompt\b`),
	regexp.MustCompile(`(?i)\byou are now\b`),
	regexp.MustCompile(`(?i)\bas an ai\b`),
	regexp.MustCompile(`(?i)\bjailbreak\b`),
	regexp.MustCompile(`(?i)\bDAN\b`),
	regexp.MustCompile(`(?i)<\s*script\b`),
	regexp.MustCompile(`(?i)<\s*iframe\b`),
}

var urlRe = regexp.MustCompile(`https?://[^\s"'<>]+`)
var controlCharsRe = regexp.MustCompile(`[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]`)
var piiPatternRe = regexp.MustCompile(`(?i)\+91 ?\d{10}|\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b`)
var badSchemeRe = regexp.MustCompile(`(?i)^(https?:\/\/)`)
var blockedHostsRe = regexp.MustCompile(`(?i)(^|[^a-z0-9-])(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])([:/]|$)`)

func validateText(text string, kind string, reasons *[]string) {
	if text == "" {
		return
	}
	if len(text) > 600 {
		*reasons = append(*reasons, kind+"_too_long")
		return
	}
	for _, p := range injectionPatterns {
		if p.MatchString(text) {
			*reasons = append(*reasons, kind+"_injection_pattern")
			return
		}
	}
	if controlCharsRe.MatchString(text) {
		*reasons = append(*reasons, kind+"_control_chars")
		return
	}
	urls := urlRe.FindAllString(text, -1)
	for _, u := range urls {
		if !badSchemeRe.MatchString(u) {
			*reasons = append(*reasons, kind+"_bad_scheme")
		}
		if blockedHostsRe.MatchString(u) {
			*reasons = append(*reasons, kind+"_internal_url")
		}
	}
}

// ValidateLLMCopy validates an LLM-produced message. On any finding, fail
// closed (do not send).
func ValidateLLMCopy(input LLMCopyInput) LLMValidationResult {
	var reasons []string
	validateText(input.Subject, "subject", &reasons)
	validateText(input.Body, "body", &reasons)
	if input.Body != "" && piiPatternRe.MatchString(input.Body) {
		reasons = append(reasons, "body_leaks_pii")
	}
	return LLMValidationResult{
		OK:      len(reasons) == 0,
		Reasons: reasons,
		Subject: input.Subject,
		Body:    input.Body,
	}
}

// CensorLLMCopy replaces known-bad tokens when a soft-pass is acceptable
// (e.g. logs). Hard reject is the default for outbound customer copy.
func CensorLLMCopy(body string) string {
	// <script …>…</script> → [blocked]
	body = regexp.MustCompile(`(?i)<script[\s\S]*?</script>`).ReplaceAllString(body, "[blocked]")
	// DAN → [blocked]
	body = regexp.MustCompile(`(?i)\bDAN\b`).ReplaceAllString(body, "[blocked]")
	// +91 1234567890 → [redacted-phone]
	body = regexp.MustCompile(`\+91 ?\d{10}`).ReplaceAllString(body, "[redacted-phone]")
	return body
}

// RenderLLMValidation renders the LLM validation result.
func RenderLLMValidation(v LLMValidationResult) string {
	if v.OK {
		return "LLM copy validation: PASS ✓"
	}
	return "LLM copy validation: FAIL — " + strings.Join(v.Reasons, ", ")
}
