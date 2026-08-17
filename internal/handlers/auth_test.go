package handlers

import (
	"strings"
	"testing"
)

func TestEmailHash_IsDeterministic(t *testing.T) {
	first := emailHash("user@example.com")
	second := emailHash("user@example.com")
	if first != second {
		t.Errorf("emailHash not deterministic: %q != %q", first, second)
	}
}

func TestEmailHash_DistinguishesAddresses(t *testing.T) {
	if emailHash("user@example.com") == emailHash("other@example.com") {
		t.Error("different emails produced the same hash")
	}
}

func TestEmailHash_DoesNotLeakAddress(t *testing.T) {
	email := "victim@example.com"
	h := emailHash(email)
	if strings.Contains(h, "victim") || strings.Contains(h, "example.com") || strings.Contains(h, "@") {
		t.Errorf("hash %q contains parts of the raw email %q", h, email)
	}
}

func TestEmailHash_IsFixedWidthHex(t *testing.T) {
	h := emailHash("user@example.com")
	if len(h) != 16 {
		t.Errorf("hash length = %d, want 16", len(h))
	}
	for _, c := range h {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Errorf("hash %q contains non-hex character %q", h, c)
		}
	}
}
