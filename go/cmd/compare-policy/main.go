package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"razor_gateway/go/rz"
)

func main() {
	configFile := flag.String("config", "", "JSON tunables file (see tunables.example.json)")
	flag.Parse()

	events, err := rz.LoadEvents("data/flows")
	if err != nil {
		fmt.Fprintln(os.Stderr, "load events:", err)
		os.Exit(1)
	}
	if *configFile != "" {
		if _, err := rz.LoadTunablesFile(*configFile); err != nil {
			fmt.Fprintln(os.Stderr, "tunables:", err)
			os.Exit(1)
		}
	}
	now := rz.BatchNow()

	dir := filepath.Join("data")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	realAudit, err := rz.NewAuditStore(filepath.Join(dir, "audit.real.jsonl"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	naiveAudit, err := rz.NewAuditStore(filepath.Join(dir, "audit.naive.jsonl"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	comparison, err := rz.ComparePolicies(events, realAudit, naiveAudit, now)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Printf("Compared REAL vs NAIVE policy over %d identical synthetic events.\n\n", len(events))
	fmt.Println(rz.RenderComparison(comparison))
}
