package policy

import (
	"encoding/json"
	"strings"
)

// Rule binds one HTTP method to one upstream path pattern.
// Path is matched against the upstream path without leading "/api/v1" prefix,
// e.g. "Voucher/Factory/saveVoucher". "*" matches one segment, "**" the rest.
type Rule struct {
	Method string `json:"method"`
	Path   string `json:"path"`
}

func Parse(raw string) ([]Rule, error) {
	var rules []Rule
	if err := json.Unmarshal([]byte(raw), &rules); err != nil {
		return nil, err
	}
	return rules, nil
}

func MustJSON(rules []Rule) string {
	b, err := json.Marshal(rules)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// Allowed reports whether method+path matches at least one rule.
// Empty rules deny everything.
func Allowed(rules []Rule, method, path string) bool {
	path = strings.TrimPrefix(strings.Trim(path, "/"), "api/v1/")
	for _, r := range rules {
		if !strings.EqualFold(r.Method, method) && r.Method != "*" {
			continue
		}
		if matchPath(r.Path, path) {
			return true
		}
	}
	return false
}

func matchPath(pattern, path string) bool {
	if pattern == "**" || pattern == "*" {
		return true
	}
	pSeg := strings.Split(strings.Trim(pattern, "/"), "/")
	sSeg := strings.Split(strings.Trim(path, "/"), "/")
	pi, si := 0, 0
	for pi < len(pSeg) && si < len(sSeg) {
		switch pSeg[pi] {
		case "**":
			return true
		case "*":
			pi++
			si++
		default:
			if !strings.EqualFold(pSeg[pi], sSeg[si]) {
				return false
			}
			pi++
			si++
		}
	}
	// trailing "**" consumes the rest
	if pi < len(pSeg) && pSeg[pi] == "**" {
		pi++
	}
	return pi == len(pSeg) && si == len(sSeg)
}

// DefaultSevdeskSync is the minimal allowlist for a sevDesk sync integration:
// voucher/tag writes, invoice reads, check-account reads.
func DefaultSevdeskSync() []Rule {
	return []Rule{
		{Method: "GET", Path: "SevClient/**"},
		{Method: "GET", Path: "CheckAccount"},
		{Method: "GET", Path: "CheckAccount/**"},
		{Method: "GET", Path: "CheckAccountTransaction"},
		{Method: "GET", Path: "CheckAccountTransaction/**"},
		{Method: "POST", Path: "CheckAccount/*/transactionMoneyTransitEvent"},
		{Method: "GET", Path: "Voucher"},
		{Method: "GET", Path: "Voucher/**"},
		{Method: "POST", Path: "Voucher/Factory/**"},
		{Method: "PUT", Path: "Voucher/**"},
		{Method: "POST", Path: "Tag/Factory/**"},
		{Method: "GET", Path: "Tag/**"},
		{Method: "GET", Path: "Invoice"},
		{Method: "GET", Path: "Invoice/**"},
		{Method: "POST", Path: "Invoice/Factory/**"},
		{Method: "PUT", Path: "Invoice/**"},
		{Method: "GET", Path: "Contact"},
		{Method: "GET", Path: "Contact/**"},
		{Method: "GET", Path: "CostCentre"},
		{Method: "GET", Path: "CostCentre/**"},
		{Method: "GET", Path: "TaxRule"},
		{Method: "GET", Path: "TaxRule/**"},
	}
}

// DefaultReadOnly allows GETs only, for reporting / BWA style consumers.
func DefaultReadOnly() []Rule {
	return []Rule{
		{Method: "GET", Path: "**"},
	}
}
