package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
)

// CallNotificationsPath is the only callback path served on the TLS listener.
const CallNotificationsPath = "/graph/call-records"

// CallNotificationsConfig starts no listener unless explicitly enabled.
// Only file paths, not key material, belong in the configuration.
type CallNotificationsConfig struct {
	Enabled     bool   `yaml:"enabled"`
	Addr        string `yaml:"addr"`
	PublicURL   string `yaml:"public_url"`
	TLSCertFile string `yaml:"tls_cert_file"`
	TLSKeyFile  string `yaml:"tls_key_file"`
}

func (c *Config) validateCallNotifications() error {
	w := c.CallNotifications
	if !w.Enabled {
		return nil
	}
	_, portText, err := net.SplitHostPort(w.Addr)
	port, portErr := strconv.Atoi(portText)
	if err != nil || portErr != nil || port < 1 || port > 65535 || strconv.Itoa(port) != portText {
		return errors.New("call_notifications.addr: explicit bind address and numeric port required")
	}
	if c.Admin.Enabled {
		_, adminPort, _ := net.SplitHostPort(c.Admin.Addr)
		if admin, _ := strconv.Atoi(adminPort); admin == port {
			return errors.New("call_notifications.addr: must use a different port from admin.addr")
		}
	}
	public, err := url.Parse(w.PublicURL)
	if err != nil || public.Scheme != "https" || public.Hostname() == "" || public.User != nil ||
		public.ForceQuery || public.RawQuery != "" || strings.Contains(w.PublicURL, "#") || public.EscapedPath() != CallNotificationsPath {
		return errors.New("call_notifications.public_url: HTTPS URL at /graph/call-records without credentials, query or fragment required")
	}
	if !filepath.IsAbs(w.TLSCertFile) || !filepath.IsAbs(w.TLSKeyFile) {
		return errors.New("call_notifications: absolute tls_cert_file and tls_key_file paths required")
	}
	configured := false
	for i, t := range c.Tenants {
		if t.CallNotificationClientStateFile != "" {
			if !filepath.IsAbs(t.CallNotificationClientStateFile) {
				return fmt.Errorf("tenants[%d].call_notification_client_state_file: absolute mounted file path required", i)
			}
			configured = true
		}
	}
	if !configured {
		return errors.New("call_notifications: at least one tenant needs call_notification_client_state_file")
	}
	return nil
}
