package main

import (
	"errors"
	"fmt"

	"github.com/rknightion/graph2otel/internal/config"
	"github.com/rknightion/graph2otel/internal/teams/geoip"
)

// The command owns these readers. Collectors borrow their tenant's reader
// until all workers have drained; they never open or close databases.
type tenantGeoIPReaders map[string]*geoip.Reader

func openTeamsGeoIP(cfg *config.Config, open func(string, string) (*geoip.Reader, error)) (tenantGeoIPReaders, error) {
	var readers tenantGeoIPReaders
	for i, t := range cfg.Tenants {
		if t.Teams == nil || t.Teams.GeoIP == (config.TeamsGeoIPConfig{}) {
			continue
		}
		paths := t.Teams.GeoIP
		r, err := open(paths.ASNDB, paths.CityDB)
		if err != nil {
			return nil, errors.Join(fmt.Errorf("tenants[%d].%w", i, err), readers.close())
		}
		if readers == nil {
			readers = make(tenantGeoIPReaders)
		}
		readers[t.TenantID] = r
	}
	return readers, nil
}

func (readers tenantGeoIPReaders) close() error {
	var err error
	for _, r := range readers {
		err = errors.Join(err, r.Close())
	}
	return err
}
