package keys

import (
	"fmt"
	"net"
	"strings"
)

// ParseAllowedIPs parses a comma-separated list of IPs and CIDRs.
// Empty input allows any IP. Plain IPs become host routes.
func ParseAllowedIPs(s string) ([]*net.IPNet, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	var out []*net.IPNet
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !strings.Contains(part, "/") {
			if ip := net.ParseIP(part); ip != nil {
				bits := 128
				if ip.To4() != nil {
					bits = 32
				}
				part = fmt.Sprintf("%s/%d", part, bits)
			} else {
				return nil, fmt.Errorf("invalid IP: %s", part)
			}
		}
		_, n, err := net.ParseCIDR(part)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR: %s", part)
		}
		out = append(out, n)
	}
	return out, nil
}

// IPAllowed reports whether ipStr matches at least one network.
// A nil network list allows everything.
func IPAllowed(nets []*net.IPNet, ipStr string) bool {
	if len(nets) == 0 {
		return true
	}
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// NormalizeAllowedIPs canonicalises user input (trims, drops empties).
func NormalizeAllowedIPs(s string) string {
	parts := strings.Split(s, ",")
	keep := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			keep = append(keep, p)
		}
	}
	return strings.Join(keep, ", ")
}
