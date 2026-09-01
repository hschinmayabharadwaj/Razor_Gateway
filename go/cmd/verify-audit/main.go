package main

import (
	"fmt"
	"os"
	"path/filepath"

	"razor_gateway/go/rz"
)

func main() {
	file := filepath.Join("data", "audit.log.jsonl")
	entries, err := rz.ReadAuditFile(file)
	if err != nil {
		fmt.Fprintln(os.Stderr, "No audit log found. Run `run-batch` first.", err)
		os.Exit(1)
	}

	result := rz.VerifyChain(entries)

	if result.Valid {
		fmt.Printf("✓ chain verified, %d entries, no tampering detected\n", result.Entries)
		return
	}

	idx := result.BrokenAtIndex
	entry := entries[idx]
	expectedPrev := rz.GenesisHash
	if idx > 0 {
		expectedPrev = entries[idx-1].Hash
	}
	if entry.PrevHash != expectedPrev {
		fmt.Printf("✗ chain broken at entry %d (%s): prevHash mismatch (expected %s…, got %s…)\n",
			idx, entry.EventID, short(expectedPrev), short(entry.PrevHash))
	} else {
		recomputed := rz.ComputeHash(entry.PrevHash, &entry)
		fmt.Printf("✗ chain broken at entry %d (%s): hash mismatch (expected %s…, got %s…)\n",
			idx, entry.EventID, short(recomputed), short(entry.Hash))
	}
	os.Exit(1)
}

func short(s string) string {
	if len(s) > 16 {
		return s[:16]
	}
	return s
}
