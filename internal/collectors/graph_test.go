package collectors

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

// fakeGraph is an in-memory GraphClient: it maps request URLs to canned
// response bodies (or errors), and records every ConsistencyLevel header seen.
type fakeGraph struct {
	bodies       map[string]string
	errs         map[string]error
	seenHeaders  []map[string]string
	requestedURL []string
}

func (f *fakeGraph) RawGet(ctx context.Context, url string) ([]byte, error) {
	return f.RawGetWithHeaders(ctx, url, nil)
}

func (f *fakeGraph) RawGetWithHeaders(_ context.Context, url string, headers map[string]string) ([]byte, error) {
	f.requestedURL = append(f.requestedURL, url)
	f.seenHeaders = append(f.seenHeaders, headers)
	if err, ok := f.errs[url]; ok {
		return nil, err
	}
	body, ok := f.bodies[url]
	if !ok {
		return nil, errors.New("fakeGraph: no canned body for " + url)
	}
	return []byte(body), nil
}

func TestCountParsesScalarAndSetsConsistencyLevel(t *testing.T) {
	const url = "https://graph.microsoft.com/v1.0/users/$count"
	g := &fakeGraph{bodies: map[string]string{url: "1234"}}

	n, err := Count(context.Background(), g, url)
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if n != 1234 {
		t.Errorf("count = %d, want 1234", n)
	}
	if len(g.seenHeaders) != 1 || g.seenHeaders[0]["ConsistencyLevel"] != "eventual" {
		t.Errorf("ConsistencyLevel header = %v, want eventual on the count request", g.seenHeaders)
	}
	// $count serves text/plain; demanding application/json returns HTTP 415.
	if g.seenHeaders[0]["Accept"] != "text/plain" {
		t.Errorf("Accept header = %q, want text/plain for a $count request", g.seenHeaders[0]["Accept"])
	}
}

func TestCountRejectsNonInteger(t *testing.T) {
	const url = "https://graph.microsoft.com/v1.0/users/$count"
	g := &fakeGraph{bodies: map[string]string{url: "not-a-number"}}

	if _, err := Count(context.Background(), g, url); err == nil {
		t.Fatal("expected an error parsing a non-integer count body")
	}
}

func TestCountPropagatesGraphError(t *testing.T) {
	const url = "https://graph.microsoft.com/v1.0/users/$count"
	g := &fakeGraph{errs: map[string]error{url: errors.New("boom")}}

	if _, err := Count(context.Background(), g, url); err == nil {
		t.Fatal("expected the Graph error to propagate")
	}
}

func TestCountViaCollectionReadsODataCountWithEventualHeader(t *testing.T) {
	const url = "https://graph.microsoft.com/v1.0/users?$filter=x&$count=true&$top=1"
	g := &fakeGraph{bodies: map[string]string{url: `{"@odata.count":57,"value":[{"id":"a"}]}`}}

	n, err := CountViaCollection(context.Background(), g, url)
	if err != nil {
		t.Fatalf("CountViaCollection: %v", err)
	}
	if n != 57 {
		t.Errorf("count = %d, want 57", n)
	}
	if g.seenHeaders[0]["ConsistencyLevel"] != "eventual" {
		t.Errorf("ConsistencyLevel header not set: %v", g.seenHeaders)
	}
}

func TestGetAllValuesFollowsNextLink(t *testing.T) {
	const page1 = "https://graph.microsoft.com/v1.0/subscribedSkus"
	const page2 = "https://graph.microsoft.com/v1.0/subscribedSkus?$skiptoken=abc"
	g := &fakeGraph{bodies: map[string]string{
		page1: `{"value":[{"id":"a"},{"id":"b"}],"@odata.nextLink":"` + page2 + `"}`,
		page2: `{"value":[{"id":"c"}]}`,
	}}

	vals, err := GetAllValues(context.Background(), g, page1, nil)
	if err != nil {
		t.Fatalf("GetAllValues: %v", err)
	}
	if len(vals) != 3 {
		t.Fatalf("got %d values, want 3 across both pages", len(vals))
	}
	var got []string
	for _, raw := range vals {
		var obj struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(raw, &obj); err != nil {
			t.Fatalf("unmarshal element: %v", err)
		}
		got = append(got, obj.ID)
	}
	if got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Errorf("element order = %v, want [a b c]", got)
	}
}

func TestGetAllValuesForwardsHeaders(t *testing.T) {
	const url = "https://graph.microsoft.com/v1.0/groups?$filter=x"
	g := &fakeGraph{bodies: map[string]string{url: `{"value":[]}`}}

	if _, err := GetAllValues(context.Background(), g, url, map[string]string{"ConsistencyLevel": "eventual"}); err != nil {
		t.Fatalf("GetAllValues: %v", err)
	}
	if g.seenHeaders[0]["ConsistencyLevel"] != "eventual" {
		t.Errorf("ConsistencyLevel header not forwarded: %v", g.seenHeaders)
	}
}
