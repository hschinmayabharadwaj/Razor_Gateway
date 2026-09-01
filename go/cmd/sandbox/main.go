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
	report, err := rz.RunSandbox(events, rz.BatchNow())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(rz.RenderSandbox(report))
}
