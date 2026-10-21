package policy

import "testing"

func TestAllowed(t *testing.T) {
	rules := DefaultSevdeskSync()
	cases := []struct {
		method string
		path   string
		want   bool
	}{
		{"POST", "Voucher/Factory/saveVoucher", true},
		{"PUT", "Voucher/123/bookAmount", true},
		{"GET", "CheckAccountTransaction", true},
		{"POST", "Contact/Factory/save", false},
		{"DELETE", "Voucher/123", false},
		{"GET", "SevUser", false},
		{"GET", "Invoice/456", true},
	}
	for _, c := range cases {
		if got := Allowed(rules, c.method, c.path); got != c.want {
			t.Errorf("Allowed(%s %s) = %v, want %v", c.method, c.path, got, c.want)
		}
	}
}

func TestMatchPath(t *testing.T) {
	if !matchPath("Voucher/**", "Voucher/1/bookAmount") {
		t.Error("** should match rest")
	}
	if !matchPath("CheckAccount/*/transactionMoneyTransitEvent", "CheckAccount/5/transactionMoneyTransitEvent") {
		t.Error("* should match single segment")
	}
	if matchPath("CheckAccount/*/transactionMoneyTransitEvent", "CheckAccount/5/other/transactionMoneyTransitEvent") {
		t.Error("* must not match multiple segments")
	}
}
