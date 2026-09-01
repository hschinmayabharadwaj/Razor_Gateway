package rz

import (
	"crypto/subtle"
)

// Access-control stub — default-DENY. Unknown or missing credentials are
// rejected before any action is considered. In production the credential store
// is a real identity provider; this is a deterministic allow-list for
// hermetic tests.

type Action string

const (
	ActionRunBatch          Action = "run_batch"
	ActionTuneSandbox       Action = "tune_sandbox"
	ActionReadAuditLog      Action = "read_audit_log"
	ActionReadExceptionList Action = "read_exception_list"
	ActionVerifyAnchor      Action = "verify_anchor"
)

type AccessDecision struct {
	Allowed bool
	Actor   string // resolved principal id, or "anonymous"
	Action  Action
	Reason  string // when denied
}

type credentialEntry struct {
	role      string
	principal string
}

// CREDENTIAL_STORE — NEVER put real secrets here.
var credentialStore = map[string]credentialEntry{
	"op_key_demo":    {role: "operator", principal: "ops-demo"},
	"admin_key_demo": {role: "admin", principal: "admin-demo"},
	"audit_key_demo": {role: "auditor", principal: "audit-demo"},
}

var rolePermissions = map[string][]Action{
	"operator": {ActionRunBatch, ActionReadAuditLog, ActionReadExceptionList, ActionVerifyAnchor},
	"admin":    {ActionRunBatch, ActionTuneSandbox, ActionReadAuditLog, ActionReadExceptionList, ActionVerifyAnchor},
	"auditor":  {ActionReadAuditLog, ActionReadExceptionList, ActionVerifyAnchor},
}

func safeEqualStrings(a, b string) bool {
	ab := []byte(a)
	bb := []byte(b)
	if len(ab) != len(bb) {
		return false
	}
	return subtle.ConstantTimeCompare(ab, bb) == 1
}

func resolve(credential string) (string, string, bool) { // role, principal, ok
	for candidate, entry := range credentialStore {
		if safeEqualStrings(candidate, credential) {
			return entry.role, entry.principal, true
		}
	}
	return "", "", false
}

func containsAction(list []Action, a Action) bool {
	for _, x := range list {
		if x == a {
			return true
		}
	}
	return false
}

// Authorize resolves a credential (API key from header/env, NEVER from URL)
// and checks the role's permission matrix.
func Authorize(credential string, action Action) AccessDecision {
	if credential == "" {
		return AccessDecision{Allowed: false, Actor: "anonymous", Action: action, Reason: "missing_credential"}
	}
	role, principal, found := resolve(credential)
	if !found {
		return AccessDecision{Allowed: false, Actor: "anonymous", Action: action, Reason: "unknown_credential"}
	}
	perms := rolePermissions[role]
	if !containsAction(perms, action) {
		return AccessDecision{Allowed: false, Actor: principal, Action: action, Reason: "forbidden_for_role"}
	}
	return AccessDecision{Allowed: true, Actor: principal, Action: action}
}

// AuthorizeResult is the generic guard result.
type AuthorizeResult[T any] struct {
	Ok     bool
	Value  T
	Denied AccessDecision
}

// Guard runs fn only if authorized; returns a rejected-style result otherwise.
func Guard[T any](credential string, action Action, fn func() T) AuthorizeResult[T] {
	d := Authorize(credential, action)
	if !d.Allowed {
		return AuthorizeResult[T]{Ok: false, Denied: d}
	}
	return AuthorizeResult[T]{Ok: true, Value: fn()}
}
