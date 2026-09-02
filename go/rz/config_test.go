package rz

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTunables(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "tunables.json")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestLoadTunablesFileApplies verifies a JSON config file mutates the tunables
// used by the decision rules, and that the returned config mirrors it.
func TestLoadTunablesFileApplies(t *testing.T) {
	defer ResetTunables()
	ResetTunables()

	p := writeTunables(t, `{"max_retry_attempts":5,"ptp_supervisor_threshold":999999,"mandate_retry_window":7}`)
	cfg, err := LoadTunablesFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MaxRetryAttempts != 5 || AtMaxRetryAttempts(5) != true {
		t.Fatalf("max_retry_attempts not applied: %+v", cfg)
	}
	if cfg.PtpSupervisorThreshold != 999999 {
		t.Fatalf("ptp threshold not applied: %d", cfg.PtpSupervisorThreshold)
	}
	if cfg.MandateWindowDays != 7 {
		t.Fatalf("mandate window not applied: %d", cfg.MandateWindowDays)
	}
	if GetTunables().MaxTouchesPerCustomer != DefaultTunables().MaxTouchesPerCustomer {
		t.Fatalf("unmentioned key changed unexpectedly")
	}
}

// TestLoadTunablesFileRejectsUnknownOrLocked proves the tunability surface is
// closed: an unknown key or a LOCKED invariant name fails loudly and applies
// nothing.
func TestLoadTunablesFileRejectsUnknownOrLocked(t *testing.T) {
	defer ResetTunables()
	ResetTunables()

	for _, bad := range []string{
		`{"fraud_flagged":1}`,
		`{"quiet_hours_end":10}`,
		`{"bogus":1}`,
		`{"max_retry_attempts":2,"nope":9}`,
	} {
		p := writeTunables(t, bad)
		if _, err := LoadTunablesFile(p); err == nil {
			t.Fatalf("config %s accepted for %s", bad, p)
		}
	}
	if got := GetTunables().MaxRetryAttempts; got != DefaultTunables().MaxRetryAttempts {
		t.Fatalf("partial application leaked: max_retry_attempts=%d", got)
	}
}

// TestLoadTunablesFileRejectsBadValues covers non-integer / negative values.
func TestLoadTunablesFileRejectsBadValues(t *testing.T) {
	defer ResetTunables()
	for _, bad := range []string{
		`{"max_retry_attempts":"three"}`,
		`{"ptp_supervisor_threshold":1.5}`,
		`{"voice_call_cap":-2}`,
		`not-json`,
	} {
		p := writeTunables(t, bad)
		if _, err := LoadTunablesFile(p); err == nil {
			t.Fatalf("config accepted for %s", bad)
		}
	}
}

// TestShippedTunablesExampleParses guarantees the checked-in example file stays
// a valid, defaults-equal config the CLIs document.
func TestShippedTunablesExampleParses(t *testing.T) {
	defer ResetTunables()
	ResetTunables()

	b, err := os.ReadFile(filepath.Join("..", "tunables.example.json"))
	if err != nil {
		t.Skipf("example file not present: %v", err)
	}
	cfg, err := LoadTunablesFile(filepath.Join("..", "tunables.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	want := DefaultTunables()
	if cfg != want {
		t.Fatalf("shipped example drifted from defaults:\n got %+v\nwant %+v", cfg, want)
	}
	_ = b
	if !strings.Contains(string(b), "max_retry_attempts") {
		t.Fatal("example file missing max_retry_attempts")
	}
}
