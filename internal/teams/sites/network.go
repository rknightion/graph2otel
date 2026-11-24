package sites

import (
	"net/netip"
	"strings"
)

// IPClass describes the address range, not actual internet reachability.
type IPClass string

const (
	IPUnknown IPClass = "" // absent, malformed or not global unicast
	IPPublic  IPClass = "public"
	IPPrivate IPClass = "private" // RFC 1918 and RFC 4193
	IPCGNAT   IPClass = "cgnat"   // RFC 6598 shared address space
)

var sharedIPv4 = netip.MustParsePrefix("100.64.0.0/10")

// ClassifyIP distinguishes private and carrier-grade NAT addresses from other
// global unicast addresses. Omit the class attribute for IPUnknown.
func ClassifyIP(ip string) IPClass {
	addr := parseIP(ip)
	switch {
	case !addr.IsGlobalUnicast():
		return IPUnknown
	case sharedIPv4.Contains(addr):
		return IPCGNAT
	case addr.IsPrivate():
		return IPPrivate
	default:
		return IPPublic
	}
}

// RelayUsed reports whether the supplied relay IP is a non-placeholder global
// unicast address. It does not infer relay use from the endpoint or reflexive IP.
func RelayUsed(relayIP string) bool {
	return parseIP(relayIP).IsGlobalUnicast()
}

func parseIP(s string) netip.Addr {
	addr, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return netip.Addr{}
	}
	return addr.WithZone("").Unmap()
}
