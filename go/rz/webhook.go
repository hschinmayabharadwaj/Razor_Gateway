package rz

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"
)

// MAX_WEBHOOK_SKEW_SECONDS is the replay window.
const MAX_WEBHOOK_SKEW_SECONDS = 300

type VerifiedWebhook struct {
	OK      bool
	EventId string
	Flow    string
	Reason  string
}

func parseSignatureHeader(header string) (t int64, s string, ok bool) {
	if header == "" {
		return
	}
	pairs := strings.Split(header, "|")
	m := map[string]string{}
	for _, kv := range pairs {
		i := strings.IndexByte(kv, '=')
		if i > 0 {
			m[kv[:i]] = kv[i+1:]
		}
	}
	if m["t"] == "" || m["s"] == "" {
		return
	}
	var v int64
	for _, c := range m["t"] {
		if c < '0' || c > '9' {
			return
		}
		v = v*10 + int64(c-'0')
	}
	return v, m["s"], true
}

func safeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	ab := []byte(a)
	bb := []byte(b)
	return hmac.Equal(ab, bb)
}

// ComputeWebhookSignature produces the Razorpay-style t=<unix>|s=<hex_hmac> value.
func ComputeWebhookSignature(secret string, t int64, rawBody string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(fmt.Sprintf("%d.%s", t, rawBody)))
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyWebhook checks freshness + HMAC. Secret MUST come from config/env
// (see secrets.go), never a hard-coded value. nowSeconds injectable for
// deterministic tests.
func VerifyWebhook(secret string, headers map[string]string, rawBody string, nowSeconds int64) (ok bool, reason string) {
	hdr := headers["x-razorpay-signature"]
	if hdr == "" {
		hdr = headers["X-Razorpay-Signature"]
	}
	t, sig, parsed := parseSignatureHeader(hdr)
	if !parsed {
		return false, "missing_or_malformed_signature"
	}

	now := nowSeconds
	if now == 0 {
		now = time.Now().Unix()
	}
	if math.Abs(float64(now-t)) > MAX_WEBHOOK_SKEW_SECONDS {
		return false, "expired_signature_replay_rejected"
	}

	expected := ComputeWebhookSignature(secret, t, rawBody)
	if !safeEqual(expected, sig) {
		return false, "signature_mismatch"
	}
	return true, ""
}

// ParseTrustedEvent extracts eventId/flow from an ALREADY VERIFIED body.
func ParseTrustedEvent(rawBody string) (eventId string, flow string, ok bool) {
	if strings.TrimSpace(rawBody) == "" {
		return "", "", false
	}
	var payload struct {
		EventID string `json:"event_id"`
		ID      string `json:"id"`
		Flow    string `json:"flow"`
		Entity  struct {
			Type string `json:"type"`
		} `json:"entity"`
	}
	if err := json.Unmarshal([]byte(rawBody), &payload); err != nil {
		return "", "", false
	}
	eventId = payload.EventID
	if eventId == "" {
		eventId = payload.ID
	}
	flow = payload.Flow
	if flow == "" {
		flow = payload.Entity.Type
	}
	if eventId == "" {
		return "", "", false
	}
	return eventId, flow, true
}
