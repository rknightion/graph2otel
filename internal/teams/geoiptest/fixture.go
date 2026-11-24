// Package geoiptest builds synthetic MaxMind databases for offline tests.
package geoiptest

import (
	"bytes"
	"encoding/binary"
	"math"
	"os"
	"path/filepath"
	"testing"
)

// ASN writes a fixture covering every address with the same ASN record.
func ASN(t *testing.T) string {
	t.Helper()
	return writeMMDB(t, "GeoLite2-ASN", mmdbMap(
		field("autonomous_system_number", []byte{0xc2, 0xfc, 0x00}), // uint32(64512)
		field("autonomous_system_organization", mmdbString("Example Network")),
	))
}

// City writes a fixture covering every address with the same location record.
func City(t *testing.T) string {
	t.Helper()
	return writeMMDB(t, "GeoLite2-City", mmdbMap(
		field("country", mmdbMap(field("iso_code", mmdbString("ZZ")))),
		field("city", mmdbMap(field("names", mmdbMap(field("en", mmdbString("Example City")))))),
		field("location", mmdbMap(field("latitude", mmdbDouble(0)), field("longitude", mmdbDouble(12.5)))),
	))
}

// Build a small MaxMind DB v2 file with a single 24-bit search-tree node. Both
// branches point to the same record, so even excluded addresses would get a
// hit if sent to the reader. See https://maxmind.github.io/MaxMind-DB/.
func writeMMDB(t *testing.T, dbType string, record []byte) string {
	t.Helper()
	var db bytes.Buffer
	db.Write([]byte{0, 0, 17, 0, 0, 17}) // node count (1) + data separator size (16)
	db.Write(make([]byte, 16))
	db.Write(record)
	db.WriteString("\xab\xcd\xefMaxMind.com")
	db.Write(mmdbMap(
		field("node_count", []byte{0xc1, 1}),   // uint32
		field("record_size", []byte{0xa1, 24}), // uint16
		field("ip_version", []byte{0xa1, 6}),   // uint16
		field("database_type", mmdbString(dbType)),
		field("languages", []byte{0x00, 0x04}),                // empty array
		field("binary_format_major_version", []byte{0xa1, 2}), // uint16
		field("binary_format_minor_version", []byte{0xa0}),    // uint16 zero
		field("build_epoch", []byte{0x01, 0x02, 1}),           // uint64
		field("description", mmdbMap()),
	))
	path := filepath.Join(t.TempDir(), "test.mmdb")
	if err := os.WriteFile(path, db.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func field(key string, value []byte) []byte {
	return append(mmdbString(key), value...)
}

func mmdbString(value string) []byte {
	if len(value) >= 29 {
		return append([]byte{0x40 | 29, fixtureByte(len(value) - 29)}, value...)
	}
	return append([]byte{0x40 | fixtureByte(len(value))}, value...)
}

func mmdbMap(fields ...[]byte) []byte {
	if len(fields) >= 29 {
		panic("synthetic MMDB only supports maps with inline lengths")
	}
	return append([]byte{0xe0 | fixtureByte(len(fields))}, bytes.Join(fields, nil)...)
}

func fixtureByte(n int) byte {
	if n < 0 || n > math.MaxUint8 {
		panic("synthetic MMDB length exceeds one byte")
	}
	return byte(n)
}

func mmdbDouble(value float64) []byte {
	return binary.BigEndian.AppendUint64([]byte{0x68}, math.Float64bits(value))
}
