package keys

import "testing"

func TestParseAllowedIPs(t *testing.T) {
	nets, err := ParseAllowedIPs("")
	if err != nil || len(nets) != 0 {
		t.Fatalf("empty must allow all: %v", err)
	}
	nets, err = ParseAllowedIPs("10.0.0.1, 192.168.0.0/24, 2001:db8::/32")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		ip   string
		want bool
	}{
		{"10.0.0.1", true},
		{"10.0.0.2", false},
		{"192.168.0.55", true},
		{"192.168.1.1", false},
		{"2001:db8::1", true},
		{"not-an-ip", false},
	} {
		if got := IPAllowed(nets, c.ip); got != c.want {
			t.Errorf("IPAllowed(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
	if _, err := ParseAllowedIPs("bogus"); err == nil {
		t.Error("expected error for bogus input")
	}
	if _, err := ParseAllowedIPs("10.0.0.0/33"); err == nil {
		t.Error("expected error for bad CIDR")
	}
	if got := NormalizeAllowedIPs(" 10.0.0.1 ,, 192.168.0.0/24 "); got != "10.0.0.1, 192.168.0.0/24" {
		t.Errorf("normalize = %q", got)
	}
}
