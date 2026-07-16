package o365activityclient

import (
	"context"
	"net/http"
	"testing"
)

// TestStartSubscription checks the documented request shape and response
// decode: POST /subscriptions/start?contentType=X.
func TestStartSubscription(t *testing.T) {
	var gotMethod, gotPath, gotContentType string
	srv := jsonServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotContentType = r.URL.Query().Get("contentType")
		_, _ = w.Write([]byte(`{"contentType":"Audit.AzureActiveDirectory","status":"enabled","webhook":null}`))
	})
	c, _ := newTestClient(t, srv, nil)

	sub, err := c.StartSubscription(context.Background(), ContentAzureActiveDirectory)
	if err != nil {
		t.Fatalf("StartSubscription: %v", err)
	}

	if gotMethod != http.MethodPost {
		t.Errorf("method = %s, want POST", gotMethod)
	}
	if want := "/api/v1.0/" + testTenantID + "/activity/feed/subscriptions/start"; gotPath != want {
		t.Errorf("path = %q, want %q", gotPath, want)
	}
	if gotContentType != string(ContentAzureActiveDirectory) {
		t.Errorf("contentType = %q, want %q", gotContentType, ContentAzureActiveDirectory)
	}
	if sub.ContentType != string(ContentAzureActiveDirectory) {
		t.Errorf("ContentType = %q", sub.ContentType)
	}
	if !sub.Enabled() {
		t.Errorf("Enabled() = false for status %q, want true", sub.Status)
	}
	if sub.Webhook != nil {
		t.Errorf("Webhook = %+v, want nil — graph2otel polls, it does not register a webhook", sub.Webhook)
	}
}

// TestStartSubscriptionSendsNoWebhook checks no webhook body is sent. Sending
// one would register a push target graph2otel has no endpoint to receive on,
// and could clobber a webhook another application configured on the tenant.
func TestStartSubscriptionSendsNoWebhook(t *testing.T) {
	var gotBodyLen int64
	srv := jsonServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotBodyLen = r.ContentLength
		_, _ = w.Write([]byte(`{"contentType":"Audit.AzureActiveDirectory","status":"enabled"}`))
	})
	c, _ := newTestClient(t, srv, nil)

	if _, err := c.StartSubscription(context.Background(), ContentAzureActiveDirectory); err != nil {
		t.Fatalf("StartSubscription: %v", err)
	}
	if gotBodyLen > 0 {
		t.Errorf("request body length = %d, want 0 — no webhook should be registered", gotBodyLen)
	}
}

// TestStartSubscriptionRejectsInvalidContentType catches an AF20020 locally.
func TestStartSubscriptionRejectsInvalidContentType(t *testing.T) {
	var called bool
	srv := jsonServer(t, func(w http.ResponseWriter, _ *http.Request) {
		called = true
		_, _ = w.Write([]byte(`{}`))
	})
	c, _ := newTestClient(t, srv, nil)

	if _, err := c.StartSubscription(context.Background(), ContentType("Audit.Bogus")); err == nil {
		t.Error("StartSubscription(invalid content type) = nil error, want an error")
	}
	if called {
		t.Error("an invalid content type reached the API, want it rejected locally")
	}
}

// TestStopSubscription checks the documented shape: POST
// /subscriptions/stop?contentType=X with an empty response body.
func TestStopSubscription(t *testing.T) {
	var gotMethod, gotPath, gotContentType string
	srv := jsonServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotContentType = r.URL.Query().Get("contentType")
		w.WriteHeader(http.StatusOK) // the documented response is empty
	})
	c, _ := newTestClient(t, srv, nil)

	if err := c.StopSubscription(context.Background(), ContentDLPAll); err != nil {
		t.Fatalf("StopSubscription: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %s, want POST", gotMethod)
	}
	if want := "/api/v1.0/" + testTenantID + "/activity/feed/subscriptions/stop"; gotPath != want {
		t.Errorf("path = %q, want %q", gotPath, want)
	}
	if gotContentType != string(ContentDLPAll) {
		t.Errorf("contentType = %q, want %q", gotContentType, ContentDLPAll)
	}
}

// TestListSubscriptionsDecodesWebhookVariants checks both documented shapes:
// a subscription with a webhook, and one where the property is present-but-null.
func TestListSubscriptionsDecodesWebhookVariants(t *testing.T) {
	srv := jsonServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[
			{"contentType":"Audit.SharePoint","status":"enabled","webhook":{"status":"enabled","address":"https://webhook.myapp.com/o365/","authId":"o365activityapinotification","expiration":null}},
			{"contentType":"Audit.Exchange","webhook":null}
		]`))
	})
	c, _ := newTestClient(t, srv, nil)

	subs, err := c.ListSubscriptions(context.Background())
	if err != nil {
		t.Fatalf("ListSubscriptions: %v", err)
	}
	if len(subs) != 2 {
		t.Fatalf("len(subs) = %d, want 2", len(subs))
	}

	if subs[0].Webhook == nil {
		t.Fatal("subs[0].Webhook = nil, want the decoded webhook")
	}
	if subs[0].Webhook.Address != "https://webhook.myapp.com/o365/" {
		t.Errorf("Webhook.Address = %q", subs[0].Webhook.Address)
	}
	if !subs[0].Enabled() {
		t.Error("subs[0].Enabled() = false, want true")
	}

	if subs[1].Webhook != nil {
		t.Errorf("subs[1].Webhook = %+v, want nil for an explicit JSON null", subs[1].Webhook)
	}
	// No status field in the response => not enabled. A subscription whose
	// status the API omits must never be assumed usable.
	if subs[1].Enabled() {
		t.Error("subs[1].Enabled() = true for a subscription with no status, want false")
	}
}

// TestListSubscriptionsEmpty checks the pre-setup state — no subscriptions
// started yet — is an empty slice rather than an error.
func TestListSubscriptionsEmpty(t *testing.T) {
	srv := jsonServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[]`))
	})
	c, _ := newTestClient(t, srv, nil)

	subs, err := c.ListSubscriptions(context.Background())
	if err != nil {
		t.Fatalf("ListSubscriptions: %v", err)
	}
	if len(subs) != 0 {
		t.Errorf("len(subs) = %d, want 0", len(subs))
	}
}

// TestSubscriptionDisabledIsTyped checks an admin-disabled subscription
// surfaces as a recognizable AF20023 so a collector can skip rather than fail.
func TestSubscriptionDisabledIsTyped(t *testing.T) {
	srv := jsonServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"code":"AF20023","message":"The subscription was disabled by a tenant admin"}}`))
	})
	c, _ := newTestClient(t, srv, nil)

	_, err := c.ListSubscriptions(context.Background())
	if !IsSubscriptionDisabled(err) {
		t.Errorf("IsSubscriptionDisabled(%v) = false, want true", err)
	}
}

// TestStatusConstants pins the wire values Enabled() compares against.
func TestStatusConstants(t *testing.T) {
	if StatusEnabled != "enabled" {
		t.Errorf("StatusEnabled = %q, want %q", StatusEnabled, "enabled")
	}
	if StatusDisabled != "disabled" {
		t.Errorf("StatusDisabled = %q, want %q", StatusDisabled, "disabled")
	}
	if !(Subscription{Status: StatusEnabled}).Enabled() {
		t.Error("Enabled() = false for StatusEnabled")
	}
	if (Subscription{Status: StatusDisabled}).Enabled() {
		t.Error("Enabled() = true for StatusDisabled")
	}
}

// TestContentTypeValid pins the five documented content types and rejects
// anything else, turning an AF20020 into a config-time error.
func TestContentTypeValid(t *testing.T) {
	want := []ContentType{
		"Audit.AzureActiveDirectory", "Audit.Exchange",
		"Audit.SharePoint", "Audit.General", "DLP.All",
	}
	got := ContentTypes()
	if len(got) != len(want) {
		t.Fatalf("ContentTypes() returned %d types, want %d", len(got), len(want))
	}
	for i, ct := range want {
		if got[i] != ct {
			t.Errorf("ContentTypes()[%d] = %q, want %q", i, got[i], ct)
		}
		if !ct.Valid() {
			t.Errorf("%q.Valid() = false, want true", ct)
		}
	}
	for _, bad := range []ContentType{"", "Audit.General ", "audit.general", "Audit.Teams", "DLP.Some"} {
		if bad.Valid() {
			t.Errorf("%q.Valid() = true, want false", bad)
		}
	}
}
