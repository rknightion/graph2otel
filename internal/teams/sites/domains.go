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

// IdentityScope describes how an observed UPN compares with the configured
// domains. It is not a directory membership or network location verdict.
type IdentityScope string

const (
	ScopeInternal IdentityScope = "internal"
	ScopeExternal IdentityScope = "external"
	ScopeUnknown  IdentityScope = "unknown"
)

// IsInternal reports whether a participant's UPN domain matches a rule.
// A false result includes unknown scope, not just external identities.
func (d Domains) IsInternal(upn string) bool { return d.Classify(upn) == ScopeInternal }

// Classify reports unknown if there are no configured domains or no usable
// UPN. Otherwise it reports internal for a match and external for a non-match.
func (d Domains) Classify(upn string) IdentityScope {
	if len(d.exact) == 0 && len(d.suffix) == 0 {
		return ScopeUnknown
	}
	local, domain, ok := strings.Cut(strings.TrimSpace(upn), "@")
	if !ok || local == "" || strings.ContainsFunc(local, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	}) {
		return ScopeUnknown
	}
	domain, ok = domainName(domain)
	if !ok {
		return ScopeUnknown
	}
	if _, ok := d.exact[domain]; ok {
		return ScopeInternal
	}
	for _, tail, more := strings.Cut(domain, "."); more; _, tail, more = strings.Cut(tail, ".") {
		if _, ok := d.suffix[tail]; ok {
			return ScopeInternal
		}
	}
	return ScopeExternal
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
