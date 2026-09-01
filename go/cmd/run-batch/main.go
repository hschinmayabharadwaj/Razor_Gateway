package main

import (
	"fmt"
	"os"
	"path/filepath"

	"razor_gateway/go/rz"
)

func main() {
	events, err := rz.LoadEvents("data/flows")
	if err != nil {
		fmt.Fprintln(os.Stderr, "load events:", err)
		os.Exit(1)
	}
	now := rz.BatchNow()

	dir := filepath.Join("data")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	audit, err := rz.NewAuditStore(filepath.Join(dir, "audit.log.jsonl"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := audit.Clear(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	result, err := rz.RunBatch(events, audit, rz.RunnerOpts{Now: now})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	log, _ := audit.All()
	metrics := rz.ComputeMetrics(log)

	fmt.Printf("Loaded %d events across 7 recovery flows.\n\n", len(events))

	fmt.Println("===== AUDIT LOG — TABLE VIEW (all flows) =====")
	fmt.Println(rz.RenderTable(log))
	fmt.Println(rz.RenderMetrics(metrics))
	fmt.Println()
	fmt.Println("===== EXCEPTION SUMMARY (LLM, for human reviewer) =====")
	fmt.Println(result.ExceptionSummary)
	fmt.Println()
	fmt.Println("===== HASH CHAIN VERIFICATION =====")
	fmt.Println(renderChain(log))
}

func renderChain(log []rz.AuditEntry) string {
	v := rz.VerifyChain(log)
	if v.Valid {
		return fmt.Sprintf("✓ chain verified: %d entries, no tampering detected", v.Entries)
	}
	return fmt.Sprintf("✗ CHAIN BROKEN at entry %d", v.BrokenAtIndex)
}
