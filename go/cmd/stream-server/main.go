package main

import (
	"flag"
	"fmt"
	"os"

	"razor_gateway/go/rz"
)

func main() {
	port := flag.String("port", "8090", "SSE server port")
	flag.Parse()
	if v := os.Getenv("PORT"); v != "" {
		*port = v
	}

	audit, err := rz.NewAuditStore("data/audit.log.jsonl")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	hub := rz.NewStreamHub()
	rz.BroadcastHub = hub

	if _, err := rz.StartStreamServer(audit, hub, ":"+*port); err != nil {
		fmt.Fprintln(os.Stderr, "stream-server:", err)
		os.Exit(1)
	}

	fmt.Printf("stream-server listening on :%s\n", *port)
	select {}
}
