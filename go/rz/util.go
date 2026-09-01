package rz

import (
	"fmt"
	"strconv"
	"time"
)

// epochMS is the current wall-clock time in epoch milliseconds.
func epochMS() int64 { return time.Now().UnixMilli() }

// BatchNow is the deterministic daytime timestamp (2026-09-01 14:30 UTC) used
// so the TRAI quiet-hour check doesn't block all voice calls at once.
func BatchNow() int64 {
	return time.Date(2026, 9, 1, 14, 30, 0, 0, time.UTC).UnixMilli()
}

// format2 formats with two decimals (JS toFixed-like for display).
func format2(v float64) string {
	return fmt.Sprintf("%.2f", v)
}

// formatJS formats a Number the way JS ToString would (drops trailing zeros).
func formatJS(v float64) string {
	return strconv.FormatFloat(v, 'f', -1, 64)
}
