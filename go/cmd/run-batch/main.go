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
	streamFlag := flag.Bool("stream", false, "start the live SSE stream server alongside the batch")
	streamPort := flag.String("stream-port", "8090", "SSE stream server port (used with --stream)")
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
	audit, err := rz.NewAuditStore(filepath.Join(dir, "audit.log.jsonl"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := audit.Clear(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	streamOn := false
	if *streamFlag {
		hub := rz.NewStreamHub()
		rz.BroadcastHub = hub
		streamSrv, err := rz.StartStreamServer(audit, hub, ":"+*streamPort)
		if err != nil {
			fmt.Fprintln(os.Stderr, "stream-server:", err)
			os.Exit(1)
		}
		_ = streamSrv
		streamOn = true
		fmt.Printf("SSE stream server listening on :%s\n", *streamPort)
		fmt.Printf("  Blazor live page: connect to http://localhost:%s/events\n", *streamPort)
		fmt.Println("Waiting for a client to connect before running the batch...")
		hub.WaitForSubscriber(nil)
		fmt.Println("Client connected; running batch...")
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

	if streamOn {
		// Keep the SSE server alive so a connected Blazor client can keep
		// receiving events (and the sandbox tamper demo keeps working).
		fmt.Println()
		fmt.Println("Batch complete. SSE stream server still serving — Ctrl-C to exit.")
		select {}
	}
}

func renderChain(log []rz.AuditEntry) string {
	v := rz.VerifyChain(log)
	if v.Valid {
		return fmt.Sprintf("✓ chain verified: %d entries, no tampering detected", v.Entries)
	}
	return fmt.Sprintf("✗ CHAIN BROKEN at entry %d", v.BrokenAtIndex)
}
