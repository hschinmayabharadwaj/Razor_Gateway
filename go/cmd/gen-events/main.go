package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"razor_gateway/go/rz"
)

func main() {
	var (
		seed  = flag.Uint("seed", uint(rz.DefaultGenSeed), "PRNG seed")
		count = flag.Int("count", 60, "total events (flows scaled proportionally; 60 == canonical batch)")
		out   = flag.String("out", filepath.Join("data", "flows"), "output directory")
	)
	flag.Parse()

	opt := rz.GenOptions{Seed: uint32(*seed)}
	if *count != 60 {
		opt.Count = *count
	}
	events := rz.GenerateEventsWith(opt)

	if err := os.MkdirAll(*out, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := rz.WriteEvents(events, *out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	counts := rz.CountsByFlow(events)
	fmt.Printf("Generated %d events (seed %d) into %s\n", len(events), *seed, *out)
	for _, f := range rz.FlowTypes {
		fmt.Printf("  %-22s %d\n", f, counts[f])
	}
}
