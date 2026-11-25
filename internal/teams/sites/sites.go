// Package sites enriches Teams network observations with tenant-defined sites.
package sites

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// Unmapped is the site name for a lookup with no match.
const Unmapped = "unmapped"

// Site describes a mapped location. A miss has Name Unmapped and no metadata.
// Coordinates of zero are valid for a mapped site.
type Site struct {
	Name, Country       string
	Latitude, Longitude float64
}

// Table is an immutable snapshot of the configured sites. A nil or empty table
// has no matches. A snapshot can be shared between goroutines.
type Table struct {
	entries map[netip.Prefix]Site
	bits    []int // configured prefix lengths, longest first
}

// MatchSource names the network field that matched a site.
type MatchSource string

const (
	MatchNone      MatchSource = "" // no match: the site is Unmapped
	MatchSubnet    MatchSource = "subnet"
	MatchIP        MatchSource = "ip_address"
	MatchReflexive MatchSource = "reflexive_ip_address"
)

// Lookup first finds the longest site prefix covering the entire reported subnet.
// A bare subnet address is treated as a host. If the subnet has no match, Lookup
// tries the endpoint IP, then the reflexive IP: the address the service saw after
// NAT. Browser clients report no subnet or endpoint IP, so for them the
// reflexive address is the only location evidence. Only a public reflexive
// address is used; a private or shared one is a provider-internal hop. Graph
// masks the last octet of some IPv4 reflexive addresses ("192.0.2.x"); a
// masked address stands for its /24 and only matches a prefix of /24 or
// shorter. The relay IP is never used for site matching.
func (t *Table) Lookup(subnet, ip, reflexive string) (Site, MatchSource) {
	if t != nil {
		if p := parseSubnet(subnet); p.IsValid() {
			if site, ok := t.match(p); ok {
				return site, MatchSubnet
			}
		}
		if addr := parseIP(ip); addr.IsValid() {
			if site, ok := t.match(netip.PrefixFrom(addr, addr.BitLen())); ok {
				return site, MatchIP
			}
		}
		if p := parseReflexive(reflexive); p.IsValid() {
			if site, ok := t.match(p); ok {
				return site, MatchReflexive
			}
		}
	}
	return Site{Name: Unmapped}, MatchNone
}

// parseReflexive returns the public reflexive address as a host prefix, or a
// masked IPv4 address ("a.b.c.x") as its /24. Anything else is invalid.
func parseReflexive(s string) netip.Prefix {
	s = strings.TrimSpace(s)
	var p netip.Prefix
	if head, ok := strings.CutSuffix(s, ".x"); ok {
		addr, err := netip.ParseAddr(head + ".0")
		if err != nil || !addr.Is4() {
			return netip.Prefix{}
		}
		p = netip.PrefixFrom(addr, 24)
	} else {
		addr := parseIP(s)
		p = netip.PrefixFrom(addr, addr.BitLen())
	}
	if !p.IsValid() || ClassifyIP(p.Addr().String()) != IPPublic {
		return netip.Prefix{}
	}
	return p
}

func (t *Table) match(p netip.Prefix) (Site, bool) {
	for _, bits := range t.bits {
		if bits <= p.Bits() {
			if site, ok := t.entries[netip.PrefixFrom(p.Addr(), bits).Masked()]; ok {
				return site, true
			}
		}
	}
	return Site{}, false
}

func parseSubnet(s string) netip.Prefix {
	if p := parsePrefix(s); p.IsValid() {
		return p
	}
	addr := parseIP(s)
	return netip.PrefixFrom(addr, addr.BitLen())
}

func parsePrefix(s string) netip.Prefix {
	p, err := netip.ParsePrefix(strings.TrimSpace(s))
	if err != nil {
		return netip.Prefix{}
	}
	if p.Addr().Is4In6() && p.Bits() >= 96 {
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	return p.Masked()
}

func parseTable(data []byte) (*Table, error) {
	reader := csv.NewReader(bytes.NewReader(bytes.TrimPrefix(data, []byte("\ufeff"))))
	reader.FieldsPerRecord = -1
	header, err := reader.Read()
	if err == io.EOF {
		return nil, fmt.Errorf("line 1: missing CSV header")
	}
	if err != nil {
		return nil, fmt.Errorf("CSV header: %w", err)
	}
	columns := []string{"subnet", "location", "country", "latitude", "longitude"}
	for i := range header {
		header[i] = strings.TrimSpace(header[i])
	}
	if !slices.Equal(header, columns) {
		line, _ := reader.FieldPos(0)
		return nil, fmt.Errorf("line %d: expected CSV header %s", line, strings.Join(columns, ","))
	}
	reader.FieldsPerRecord = len(columns)

	table := &Table{entries: make(map[netip.Prefix]Site)}
	var lengths [129]bool // all legal IPv4 and IPv6 prefix lengths
	for {
		row, readErr := reader.Read()
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, fmt.Errorf("CSV row: %w", readErr)
		}
		prefix, site, rowErr := parseRow(reader, row)
		if rowErr != nil {
			return nil, rowErr
		}
		if _, exists := table.entries[prefix]; exists {
			line, _ := reader.FieldPos(0)
			return nil, fmt.Errorf("line %d: duplicate subnet", line)
		}
		table.entries[prefix] = site
		lengths[prefix.Bits()] = true
	}
	for bits := len(lengths) - 1; bits >= 0; bits-- {
		if lengths[bits] {
			table.bits = append(table.bits, bits)
		}
	}
	return table, nil
}

func parseRow(reader *csv.Reader, row []string) (netip.Prefix, Site, error) {
	fail := func(field int, reason string) (netip.Prefix, Site, error) {
		line, _ := reader.FieldPos(field)
		return netip.Prefix{}, Site{}, fmt.Errorf("line %d: %s", line, reason)
	}
	prefix := parsePrefix(row[0])
	if !prefix.IsValid() {
		return fail(0, "subnet must be an IPv4 or IPv6 CIDR prefix")
	}
	name := strings.TrimSpace(row[1])
	if name == "" || name == Unmapped {
		return fail(1, "location must be non-empty and not 'unmapped'")
	}
	country := strings.TrimSpace(row[2])
	if country == "" {
		return fail(2, "country must be non-empty")
	}
	lat, ok := coordinate(row[3], 90)
	if !ok {
		return fail(3, "latitude must be a finite number between -90 and 90")
	}
	lon, ok := coordinate(row[4], 180)
	if !ok {
		return fail(4, "longitude must be a finite number between -180 and 180")
	}
	return prefix, Site{Name: name, Country: country, Latitude: lat, Longitude: lon}, nil
}

func coordinate(text string, limit float64) (float64, bool) {
	value, err := strconv.ParseFloat(strings.TrimSpace(text), 64)
	return value, err == nil && value >= -limit && value <= limit
}
