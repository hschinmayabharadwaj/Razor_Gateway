package rz

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// Tamper-evident hash chain over the append-only audit log.
// ADDITIVE ONLY: we do not change the existing entry schema — we append two
// new fields (prevHash, hash) to every entry. Each entry's hash commits to the
// previous entry's hash, forming a chain that makes any edit detectable.

const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// StablePayload is the stable key-sorted stringify of an entry, ALWAYS excluding
// prevHash/hash so the hash does not self-reference. Optional fields that were
// never set are omitted (mirroring JS). Sorted keys via encoding/json maps.
func StablePayload(e *AuditEntry) string {
	m := map[string]any{
		"eventId":      e.EventID,
		"timestamp":    e.Timestamp,
		"flow":         string(e.Flow),
		"reasonBucket": string(e.ReasonBucket),
		"ruleFired":    string(e.RuleFired),
		"decision":     string(e.Decision),
		"actor":        string(e.Actor),
		"outcome":      e.Outcome,
		"state":        string(e.State),
	}
	if e.Attempt != nil {
		m["attempt"] = *e.Attempt
	}
	if e.Amount != nil {
		m["amount"] = *e.Amount
	}
	if e.Currency != "" {
		m["currency"] = e.Currency
	}
	if e.InvoiceID != "" {
		m["invoiceId"] = e.InvoiceID
	}
	if e.CustomerID != "" {
		m["customerId"] = e.CustomerID
	}
	if e.Channel != "" {
		m["channel"] = e.Channel
	}
	if e.Notes != "" {
		m["notes"] = e.Notes
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// Sha256Hex returns the hex SHA-256 digest of input.
func Sha256Hex(input string) string {
	h := sha256.Sum256([]byte(input))
	return hex.EncodeToString(h[:])
}

// ComputeHash hashes an entry given its prevHash.
func ComputeHash(prevHash string, e *AuditEntry) string {
	return Sha256Hex(prevHash + StablePayload(e))
}

// AppendAuditEntry returns the log with the new hashed entry appended.
// Pure: does NOT mutate the input slice.
func AppendAuditEntry(log []AuditEntry, newEntryData AuditEntry) []AuditEntry {
	prevHash := GenesisHash
	if len(log) > 0 {
		prevHash = log[len(log)-1].Hash
	}
	entry := newEntryData
	entry.PrevHash = prevHash
	entry.Hash = ComputeHash(prevHash, &newEntryData)
	out := make([]AuditEntry, len(log)+1)
	copy(out, log)
	out[len(log)] = entry
	return out
}

// ChainVerification reports chain validity.
type ChainVerification struct {
	Valid         bool
	BrokenAtIndex int // -1 when valid
	Entries       int
}

func NewChainVerification(valid bool, brokenAtIndex int, entries int) ChainVerification {
	return ChainVerification{Valid: valid, BrokenAtIndex: brokenAtIndex, Entries: entries}
}

// VerifyChain recomputes the entire chain from scratch and returns the first
// broken index (-1 if the whole chain verifies).
func VerifyChain(log []AuditEntry) ChainVerification {
	for i := range log {
		entry := log[i]
		expectedPrev := GenesisHash
		if i > 0 {
			expectedPrev = log[i-1].Hash
		}
		if entry.PrevHash != expectedPrev {
			return NewChainVerification(false, i, len(log))
		}
		recomputed := ComputeHash(entry.PrevHash, &entry)
		if entry.Hash != recomputed {
			return NewChainVerification(false, i, len(log))
		}
	}
	return NewChainVerification(true, -1, len(log))
}
