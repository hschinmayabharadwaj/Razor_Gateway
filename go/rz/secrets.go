package rz

import "os"

// Secrets management policy.
// RULE: no secret is ever hard-coded or committed. All secrets come from the
// environment (or a secrets manager injected at deploy time). This file is the
// single gate for reading them, so the policy is stated in one place and the
// test suite can prove we never fall back to a literal.

const REDACT = "********"

// RequireSecret reads a required secret. Panics if absent so a misconfigured
// deploy fails closed (never runs with a blank/default secret).
func RequireSecret(name string) string {
	v := os.Getenv(name)
	if v == "" {
		panic("Required secret '" + name + "' is not set (env only, never committed)")
	}
	return v
}

// OptionalSecret reads an optional secret; returns empty string if unset.
func OptionalSecret(name string) string {
	return os.Getenv(name)
}

// TEST_ONLY_SECRET is a stable, obviously-non-secret key for unit tests.
// NOT used in production paths — production webhook verification ALWAYS goes
// through RequireSecret.
const TEST_ONLY_SECRET = "webhook_secret_for_unit_tests_only"

// RedactSecret returns a redacted summary of a secret value.
func RedactSecret(value string) string {
	if len(value) == 0 {
		return REDACT
	}
	if len(value) <= 8 {
		return REDACT
	}
	return value[:2] + "…" + value[len(value)-2:] + " (len " + itoa(len(value)) + ")"
}
