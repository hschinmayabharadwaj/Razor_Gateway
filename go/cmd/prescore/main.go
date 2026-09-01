package main

import (
	"fmt"
	"os"

	"razor_gateway/go/rz"
)

func main() {
	events, err := rz.LoadEvents("data/flows")
	if err != nil {
		fmt.Fprintln(os.Stderr, "load events:", err)
		os.Exit(1)
	}
	now := rz.BatchNow()

	report, err := rz.ComputePrescoreReportPublic(events, now)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(rz.RenderPrescoreReport(report.Report))
	fmt.Println()
	fmt.Printf("Prescore entries appended: %d | total log: %d\n", report.Emitted, report.TotalLog)
	if report.ChainValid {
		fmt.Printf("✓ chain verified: %d entries, no tampering detected\n", report.TotalLog)
	} else {
		fmt.Printf("✗ CHAIN BROKEN at entry %d\n", report.BrokenAtIndex)
		os.Exit(1)
	}
}
