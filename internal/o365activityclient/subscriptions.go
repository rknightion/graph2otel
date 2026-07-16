package o365activityclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

// Subscription status values returned by the API.
const (
	// StatusEnabled means content can be listed and retrieved.
	StatusEnabled = "enabled"
	// StatusDisabled means an admin disabled the subscription; listing and
	// retrieving content fail with AF20023 until it is restarted.
	StatusDisabled = "disabled"
)

// Webhook is the optional push-notification target of a subscription.
//
// graph2otel does not use webhooks — it has no inbound HTTP endpoint, and
// polling /subscriptions/content is fully supported — but the field is modeled
// so ListSubscriptions faithfully reports a webhook configured by some OTHER
// application on the same tenant, rather than silently hiding it.
type Webhook struct {
	Address    string `json:"address"`
	AuthID     string `json:"authId"`
	Status     string `json:"status"`
	Expiration string `json:"expiration"`
}

// Subscription is one content-type subscription for this tenant.
type Subscription struct {
	ContentType string `json:"contentType"`
	Status      string `json:"status"`
	// Webhook is nil when the subscription has no webhook — the normal case for
	// a poll-based consumer. The API returns the property present-but-null.
	Webhook *Webhook `json:"webhook"`
}

// Enabled reports whether content can currently be listed and retrieved for
// this subscription.
func (s Subscription) Enabled() bool { return s.Status == StatusEnabled }

// StartSubscription starts a subscription to ct, so the service begins
// aggregating that content type's activity into blobs for this tenant.
//
// This is a WRITE — the second break in graph2otel's read-only property, after
// the Intune reports-export job — and it has two operational constraints that
// make it a setup action rather than something a poll loop calls:
//
//   - a 15-minute cooldown between start calls (stop has no cooldown), and
//   - up to 12 hours before the first content blobs appear.
//
// Starting an already-started subscription is not an error: the API treats it
// as an update, which is why this is safe to call once at startup without first
// checking ListSubscriptions.
func (c *Client) StartSubscription(ctx context.Context, ct ContentType) (Subscription, error) {
	if !ct.Valid() {
		return Subscription{}, fmt.Errorf("o365activityclient: invalid content type %q", ct)
	}
	u := c.feedURL("subscriptions/start", url.Values{"contentType": {string(ct)}})

	// No webhook: graph2otel polls. Sending no body at all leaves the
	// subscription's existing webhook (if another app configured one) untouched.
	body, _, err := c.do(ctx, http.MethodPost, u, nil)
	if err != nil {
		return Subscription{}, err
	}

	var sub Subscription
	if err := json.Unmarshal(body, &sub); err != nil {
		return Subscription{}, fmt.Errorf("o365activityclient: decode start response: %w", err)
	}
	return sub, nil
}

// StopSubscription stops the subscription to ct.
//
// Stopping is destructive in a way worth stating: content that became available
// between a stop and a later restart can NEVER be retrieved. A restart resumes
// from that point forward only, so this is not a pause button.
func (c *Client) StopSubscription(ctx context.Context, ct ContentType) error {
	if !ct.Valid() {
		return fmt.Errorf("o365activityclient: invalid content type %q", ct)
	}
	u := c.feedURL("subscriptions/stop", url.Values{"contentType": {string(ct)}})
	_, _, err := c.do(ctx, http.MethodPost, u, nil)
	return err
}

// ListSubscriptions returns the tenant's current subscriptions. An empty slice
// means none have been started — the expected state before setup, not a fault.
func (c *Client) ListSubscriptions(ctx context.Context) ([]Subscription, error) {
	u := c.feedURL("subscriptions/list", nil)
	body, _, err := c.do(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}

	var subs []Subscription
	if err := json.Unmarshal(body, &subs); err != nil {
		return nil, fmt.Errorf("o365activityclient: decode subscriptions list: %w", err)
	}
	return subs, nil
}
