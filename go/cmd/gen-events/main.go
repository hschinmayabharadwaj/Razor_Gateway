package main

import (
	"fmt"
	"os"
	"path/filepath"

	"razor_gateway/go/rz"
)

func main() {
	events := rz.GenerateEvents(0)
	dir := filepath.Join("data", "flows")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := rz.WriteEvents(events, dir); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	counts := rz.CountsByFlow(events)
	fmt.Printf("Generated %d events into %s\n", len(events), dir)
	for _, f := range rz.FlowTypes {
		fmt.Printf("  %-22s %d\n", f, counts[f])
	}
}
