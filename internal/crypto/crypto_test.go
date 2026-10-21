package crypto

import "testing"

func TestRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	sealed, err := Seal(key, "god-secret-123")
	if err != nil {
		t.Fatal(err)
	}
	pt, err := Open(key, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if pt != "god-secret-123" {
		t.Fatalf("got %q", pt)
	}
	// nondeterministic nonce
	again, _ := Seal(key, "god-secret-123")
	if again == sealed {
		t.Error("expected distinct ciphertexts")
	}
	if _, err := Open(key, "v0:bogus"); err == nil {
		t.Error("expected version error")
	}
}

func TestResolveKey(t *testing.T) {
	if _, err := ResolveKey(""); err == nil {
		t.Error("expected error for empty key")
	}
	good := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	k, err := ResolveKey(good)
	if err != nil || len(k) != 32 {
		t.Fatalf("valid key rejected: %v", err)
	}
	if _, err := ResolveKey("zz"); err == nil {
		t.Error("expected hex error")
	}
	if _, err := ResolveKey("00"); err == nil {
		t.Error("expected length error")
	}
}
