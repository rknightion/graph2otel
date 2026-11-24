// Package geoip enriches Teams reflexive IPs using local MaxMind databases.
package geoip

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/oschwald/maxminddb-golang/v2"
)

// Reader holds the configured databases. Lookups may run concurrently; stop
// them before closing the reader. A nil Reader has enrichment disabled.
type Reader struct {
	asn  *maxminddb.Reader
	city *maxminddb.Reader
}

// Result contains only the enrichment fields. Empty strings, zero ASN and nil
// coordinates indicate absent data. A coordinate of zero is valid when present.
type Result struct {
	ASN          uint32
	Organization string
	CountryCode  string
	City         string
	Latitude     *float64
	Longitude    *float64
}

// Open opens whichever database paths are configured. Call it at startup and
// close the reader at shutdown. It returns a nil reader if both paths are empty.
func Open(asnPath, cityPath string) (*Reader, error) {
	if asnPath == "" && cityPath == "" {
		return nil, nil
	}
	r := &Reader{}
	var err error
	r.asn, err = openDB("asn_db", asnPath)
	if err != nil {
		return nil, err
	}
	r.city, err = openDB("city_db", cityPath)
	if err != nil {
		return nil, errors.Join(err, r.Close())
	}
	return r, nil
}

func openDB(key, path string) (*maxminddb.Reader, error) {
	if path == "" {
		return nil, nil
	}
	db, err := maxminddb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("teams.geoip.%s: open %q: %w", key, path, err)
	}
	return db, nil
}

// Lookup takes the endpoint's reflexive and relay IP strings, not host:ports.
// Only the public reflexive IP is eligible, and never if it equals the relay.
// A skipped or missing address returns an empty Result without an error. If
// one database fails to decode, the other can still provide its fields.
func (r *Reader) Lookup(reflexiveIP, relayIP string) (Result, error) {
	if r == nil {
		return Result{}, nil
	}
	ip, err := netip.ParseAddr(reflexiveIP)
	if err != nil || ip.Zone() != "" {
		return Result{}, nil
	}
	ip = ip.Unmap()
	if !isPublic(ip) {
		return Result{}, nil
	}
	if relay, err := netip.ParseAddr(relayIP); err == nil && ip == relay.WithZone("").Unmap() {
		return Result{}, nil
	}

	var result Result
	var asnErr, cityErr error
	if r.asn != nil && (ip.Is4() || r.asn.Metadata.IPVersion == 6) {
		var record struct {
			Number       uint32 `maxminddb:"autonomous_system_number"`
			Organization string `maxminddb:"autonomous_system_organization"`
		}
		if err := r.asn.Lookup(ip).Decode(&record); err != nil {
			asnErr = fmt.Errorf("teams.geoip.asn_db: lookup: %w", err)
		} else {
			result.ASN, result.Organization = record.Number, record.Organization
		}
	}
	if r.city != nil && (ip.Is4() || r.city.Metadata.IPVersion == 6) {
		var record struct {
			Country struct {
				ISOCode string `maxminddb:"iso_code"`
			} `maxminddb:"country"`
			City struct {
				Names struct {
					English string `maxminddb:"en"`
				} `maxminddb:"names"`
			} `maxminddb:"city"`
			Location struct {
				Latitude  *float64 `maxminddb:"latitude"`
				Longitude *float64 `maxminddb:"longitude"`
			} `maxminddb:"location"`
		}
		if err := r.city.Lookup(ip).Decode(&record); err != nil {
			cityErr = fmt.Errorf("teams.geoip.city_db: lookup: %w", err)
		} else {
			result.CountryCode, result.City = record.Country.ISOCode, record.City.Names.English
			result.Latitude, result.Longitude = record.Location.Latitude, record.Location.Longitude
		}
	}
	return result, errors.Join(asnErr, cityErr)
}

// IsGlobalUnicast includes private and some special-purpose addresses. Exclude
// ranges that cannot identify a public participant, including transition and
// protocol-assignment blocks. See the IANA IPv4 and IPv6 Special-Purpose
// Address Registries.
var nonParticipantPrefixes = [...]netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.PrefixFrom(netip.AddrFrom4([4]byte{100, 64}), 10),     // RFC 6598 shared address space
	netip.MustParsePrefix("192.0.0.0/24"),                       // protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),                       // documentation
	netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 88, 99}), 24), // RFC 7526 deprecated relay anycast
	netip.MustParsePrefix("198.18.0.0/15"),                      // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"),                    // documentation
	netip.MustParsePrefix("203.0.113.0/24"),                     // documentation
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001::/23"),     // protocol assignments, including Teredo
	netip.MustParsePrefix("2001:db8::/32"), // documentation
	netip.MustParsePrefix("2002::/16"),     // 6to4
	netip.MustParsePrefix("3fff::/20"),     // documentation
}

var ipv6GlobalUnicast = netip.MustParsePrefix("2000::/3")

func isPublic(ip netip.Addr) bool {
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || (ip.Is6() && !ipv6GlobalUnicast.Contains(ip)) {
		return false
	}
	for _, prefix := range nonParticipantPrefixes {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}

// Close releases the local database files. It is safe on a nil Reader.
func (r *Reader) Close() error {
	if r == nil {
		return nil
	}
	var asnErr, cityErr error
	if r.asn != nil {
		asnErr = r.asn.Close()
	}
	if r.city != nil {
		cityErr = r.city.Close()
	}
	return errors.Join(asnErr, cityErr)
}
