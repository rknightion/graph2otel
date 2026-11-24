package sites

import (
	"fmt"
	"strings"
	"unicode"
)

// Domains is an immutable set of internal-domain rules. Its zero value marks
// nobody internal.
type Domains struct {
	exact  map[string]struct{}
	suffix map[string]struct{}
}

// NewDomains validates and compiles case-insensitive DNS domain rules. A bare
// domain matches only itself. A "*." rule matches proper subdomains at any
// depth, not the domain itself. An optional trailing DNS root dot is ignored.
func NewDomains(rules []string) (Domains, error) {
	if len(rules) == 0 {
		return Domains{}, nil
	}
	d := Domains{exact: make(map[string]struct{}), suffix: make(map[string]struct{})}
	for i, rule := range rules {
		name, wildcard := strings.CutPrefix(strings.TrimSpace(rule), "*.")
		name, ok := domainName(name)
		if !ok {
			return Domains{}, fmt.Errorf("teams.internal_domains entry %d: expected a DNS domain or '*.domain'", i+1)
		}
		if wildcard {
			d.suffix[name] = struct{}{}
		} else {
			d.exact[name] = struct{}{}
		}
	}
	return d, nil
}

// IsInternal reports whether a participant's UPN domain matches a rule.
// An absent or malformed UPN is not internal. Do not use this to drop records.
func (d Domains) IsInternal(upn string) bool {
	if len(d.exact) == 0 && len(d.suffix) == 0 {
		return false
	}
	local, domain, ok := strings.Cut(strings.TrimSpace(upn), "@")
	if !ok || local == "" || strings.ContainsFunc(local, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	}) {
		return false
	}
	domain, ok = domainName(domain)
	if !ok {
		return false
	}
	if _, ok := d.exact[domain]; ok {
		return true
	}
	for _, tail, more := strings.Cut(domain, "."); more; _, tail, more = strings.Cut(tail, ".") {
		if _, ok := d.suffix[tail]; ok {
			return true
		}
	}
	return false
}

func domainName(name string) (string, bool) {
	name = strings.TrimSuffix(name, ".")
	if len(name) == 0 || len(name) > 253 {
		return "", false
	}
	for label := range strings.SplitSeq(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for _, r := range label {
			switch {
			case 'a' <= r && r <= 'z', 'A' <= r && r <= 'Z', '0' <= r && r <= '9', r == '-':
			default:
				return "", false
			}
		}
	}
	return strings.ToLower(name), true
}
