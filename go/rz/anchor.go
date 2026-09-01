package rz

// External anchor for the audit hash chain.
//
// A raw hash chain is tamper-evident against AFTER-THE-FACT editing, but
// someone with write access to the whole log can regenerate a consistent fake
// chain from scratch. The fix is an EXTERNAL anchor: periodically publish the
// current chain root hash to a separate, append-only / write-once store that
// the recovery engine does NOT control. Because the anchor lives outside the
// log, a rebuilt chain will no longer match the already-published roots.
//
// This module models the anchor *protocol*; the durable sink is injected.

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

const GENESIS_ANCHOR = "0000000000000000000000000000000000000000000000000000000000000000"

// AnchorSink is the minimal append-only anchor store. In production this is an
// external write-once service; here a slice-backed impl keeps the tests
// hermetic while keeping the interface identical to a real append-only store.
type AnchorSink interface {
	Append(anchor PublishedAnchor)
	All() []PublishedAnchor
	Latest() *PublishedAnchor
}

type PublishedAnchor struct {
	CreatedAtMs   int64
	ChainTailHash string
	Root          string
}

type anchorSink struct {
	store []PublishedAnchor
}

func NewAnchorSink() AnchorSink { return &anchorSink{} }

func (s *anchorSink) Append(a PublishedAnchor) { s.store = append(s.store, a) }

func (s *anchorSink) All() []PublishedAnchor {
	out := make([]PublishedAnchor, len(s.store))
	copy(out, s.store)
	return out
}

func (s *anchorSink) Latest() *PublishedAnchor {
	if len(s.store) == 0 {
		return nil
	}
	a := s.store[len(s.store)-1]
	return &a
}

func sha256Hex(data string) string {
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}

// PublishAnchor commits the current chain tail to the external anchor sink.
func PublishAnchor(log []AuditEntry, sink AnchorSink, createdAtMs int64) PublishedAnchor {
	chainTailHash := GenesisHash
	if len(log) > 0 {
		chainTailHash = log[len(log)-1].Hash
	}
	latest := sink.Latest()
	prevRoot := GENESIS_ANCHOR
	if latest != nil {
		prevRoot = latest.Root
	}
	root := sha256Hex(prevRoot + chainTailHash)
	a := PublishedAnchor{
		CreatedAtMs:   createdAtMs,
		ChainTailHash: chainTailHash,
		Root:          root,
	}
	sink.Append(a)
	return a
}

type AnchorCheck struct {
	Consistent   bool
	LatestRoot   *string
	ComputedRoot *string
	Reason       string
}

func strPtr(s string) *string { return &s }

// VerifyAnchor reconfirms the current log tail against the most recently
// published anchor. If the chain was rebuilt, either the tail hash or the
// chained root will no longer match.
func VerifyAnchor(log []AuditEntry, sink AnchorSink) AnchorCheck {
	latest := sink.Latest()
	if latest == nil {
		return AnchorCheck{Consistent: false, Reason: "no_anchor_published"}
	}
	computedTail := GenesisHash
	if len(log) > 0 {
		computedTail = log[len(log)-1].Hash
	}
	if computedTail != latest.ChainTailHash {
		return AnchorCheck{
			Consistent: false,
			LatestRoot: strPtr(latest.Root),
			Reason:     "tail_hash_mismatch",
		}
	}
	// Recompute the root chain from the first anchor to the latest.
	all := sink.All()
	recomputed := GENESIS_ANCHOR
	for _, a := range all {
		recomputed = sha256Hex(recomputed + a.ChainTailHash)
	}
	if recomputed != latest.Root {
		return AnchorCheck{
			Consistent:   false,
			LatestRoot:   strPtr(latest.Root),
			ComputedRoot: strPtr(recomputed),
			Reason:       "root_chain_mismatch",
		}
	}
	return AnchorCheck{
		Consistent:   true,
		LatestRoot:   strPtr(latest.Root),
		ComputedRoot: strPtr(recomputed),
	}
}

// RenderAnchorCheck renders an anchor verification result.
func RenderAnchorCheck(label string, check AnchorCheck) string {
	if check.Consistent {
		return "anchor[" + label + "]: CONSISTENT ✓"
	}
	return "anchor[" + label + "]: INCONSISTENT — reason=" + check.Reason
}

// NowMs returns the current wall-clock time in epoch milliseconds.
func NowMs() int64 { return time.Now().UnixMilli() }
