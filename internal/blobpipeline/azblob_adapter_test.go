package blobpipeline

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
)

// fakeCredential is a stand-in azcore.TokenCredential for offline tests,
// mirroring the seam logpipeline's and graphclient's own tests use.
type fakeCredential struct{}

func (fakeCredential) GetToken(_ context.Context, _ policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "test-token"}, nil
}

// newTestSource points the real azblob client at an httptest server. It must be
// a TLS server: azcore refuses to attach a bearer token to a plaintext endpoint,
// so a plain httptest.NewServer would fail before any request is made.
func newTestSource(t *testing.T, h http.Handler) Source {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)

	client, err := azblob.NewClient(srv.URL, fakeCredential{}, &azblob.ClientOptions{
		ClientOptions: azcore.ClientOptions{Transport: srv.Client()},
	})
	if err != nil {
		t.Fatalf("azblob.NewClient: %v", err)
	}
	return &azureSource{client: client}
}

const listXML = `<?xml version="1.0" encoding="utf-8"?>
<EnumerationResults ServiceEndpoint="https://x.blob.core.windows.net/" ContainerName="insights-logs-test">
  <Prefix>tenantId=t1/</Prefix>
  <Blobs>
    <Blob>
      <Name>tenantId=t1/y=2026/m=07/d=16/h=13/m=00/PT1H.json</Name>
      <Properties><Content-Length>6104227</Content-Length><BlobType>AppendBlob</BlobType></Properties>
    </Blob>
    <Blob>
      <Name>tenantId=t1/y=2026/m=07/d=16/h=14/m=00/PT1H.json</Name>
      <Properties><Content-Length>1352505</Content-Length><BlobType>AppendBlob</BlobType></Properties>
    </Blob>
  </Blobs>
  <NextMarker />
</EnumerationResults>`

func TestAzureSourceListDecodesNamesAndSizes(t *testing.T) {
	var gotQuery string
	src := newTestSource(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(listXML))
	}))

	got, err := src.List(context.Background(), "insights-logs-test", "tenantId=t1/")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("List returned %d blobs, want 2", len(got))
	}
	if got[0].Name != "tenantId=t1/y=2026/m=07/d=16/h=13/m=00/PT1H.json" || got[0].Size != 6104227 {
		t.Errorf("blob[0] = %+v, want the name and Content-Length from the listing", got[0])
	}
	// The prefix must reach the wire. A listing that quietly drops it would
	// return every tenant's blobs on a shared account.
	if !strings.Contains(gotQuery, "prefix=tenantId%3Dt1%2F") {
		t.Errorf("list query = %q, want it to carry the prefix", gotQuery)
	}
}

// The whole engine rests on ranged reads. If the Range header does not reach
// the wire, every tick re-downloads whole multi-megabyte blobs and re-emits
// every record — an expensive, silent correctness failure.
func TestAzureSourceReadRangeSendsTheRangeHeader(t *testing.T) {
	var gotRange string
	src := newTestSource(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRange = r.Header.Get("x-ms-range")
		if gotRange == "" {
			gotRange = r.Header.Get("Range")
		}
		_, _ = w.Write([]byte("payload"))
	}))

	got, err := src.ReadRange(context.Background(), "insights-logs-test", "blob.json", 100, 50)
	if err != nil {
		t.Fatalf("ReadRange: %v", err)
	}
	if string(got) != "payload" {
		t.Errorf("ReadRange returned %q, want the response body", got)
	}
	if want := "bytes=100-149"; gotRange != want {
		t.Errorf("range header = %q, want %q", gotRange, want)
	}
}

// A zero count must not become "download the whole blob", which is exactly what
// azblob's HTTPRange means by an all-zero range.
func TestAzureSourceReadRangeRejectsAZeroCountWithoutCallingAzure(t *testing.T) {
	called := false
	src := newTestSource(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		_, _ = w.Write([]byte("the entire blob"))
	}))

	got, err := src.ReadRange(context.Background(), "c", "blob.json", 0, 0)
	if err != nil {
		t.Fatalf("ReadRange: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("ReadRange(count=0) returned %q, want nothing", got)
	}
	if called {
		t.Error("ReadRange(count=0) issued a request; azblob would have treated the zero range as 'whole blob'")
	}
}

// A 403 on the read path is the documented data-plane RBAC trap (Owner can list
// but not read blob content). It must surface as an error, never as an empty
// read that looks like "no new data".
func TestAzureSourceReadRangeSurfacesAuthorizationFailures(t *testing.T) {
	src := newTestSource(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`<?xml version="1.0"?><Error><Code>AuthorizationPermissionMismatch</Code></Error>`))
	}))

	if _, err := src.ReadRange(context.Background(), "c", "blob.json", 0, 10); err == nil {
		t.Fatal("ReadRange returned nil error on a 403; a missing Storage Blob Data Reader role would look like an empty blob")
	}
}

func TestAzureSourceListSurfacesErrors(t *testing.T) {
	src := newTestSource(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`<?xml version="1.0"?><Error><Code>ContainerNotFound</Code></Error>`))
	}))

	if _, err := src.List(context.Background(), "nope", "p/"); err == nil {
		t.Fatal("List returned nil error for a missing container; the tick would look successful")
	}
}

// azblob.NewClient itself accepts a malformed URL and fails only on the first
// request, so a config typo would surface as a recurring per-tick error rather
// than a startup failure naming the bad value. NewAzureSource validates instead.
func TestNewAzureSourceRejectsUnusableAccountURLs(t *testing.T) {
	for _, tc := range []struct{ name, url string }{
		{"malformed", "://not a url"},
		{"empty", ""},
		{"no host", "https://"},
		{"plaintext", "http://graph2otelm7kni.blob.core.windows.net"}, // azcore refuses bearer tokens over http
		{"bare account name", "graph2otelm7kni"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewAzureSource(tc.url, fakeCredential{}); err == nil {
				t.Errorf("NewAzureSource(%q) = nil error, want a startup failure", tc.url)
			}
		})
	}
}

func TestNewAzureSourceAcceptsARealAccountURL(t *testing.T) {
	if _, err := NewAzureSource("https://graph2otelm7kni.blob.core.windows.net", fakeCredential{}); err != nil {
		t.Fatalf("NewAzureSource rejected a valid account URL: %v", err)
	}
}
