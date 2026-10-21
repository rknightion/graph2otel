package graphclient

import (
	"bytes"
	"fmt"
	"io"
	"net/http"

	nethttplibrary "github.com/microsoft/kiota-http-go"
)

// replayBodyRetry preserves Kiota's retry policy but gives every attempt its
// own reader and headers. RoundTrip may return before net/http finishes reading
// the previous body; seeking that shared reader for a retry races with the
// previous attempt. Snapshot at the retry boundary, where the payload may
// already be compressed depending on Kiota's default middleware order.
type replayBodyRetry struct{ next nethttplibrary.Middleware }

func (r *replayBodyRetry) Intercept(pipeline nethttplibrary.Pipeline, index int, req *http.Request) (*http.Response, error) {
	if req.Body == nil || req.Body == http.NoBody || req.ContentLength < 0 {
		return r.next.Intercept(pipeline, index, req)
	}
	defer req.Body.Close()
	// RawPost and Kiota already hold these JSON request bodies in memory.
	payload, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, fmt.Errorf("graphclient: snapshot retry body: %w", err)
	}
	callReq := req.Clone(req.Context())
	callReq.Body = nethttplibrary.NopCloser(bytes.NewReader(payload))
	callReq.GetBody = func() (io.ReadCloser, error) { return nethttplibrary.NopCloser(bytes.NewReader(payload)), nil }
	return r.next.Intercept(&bodyReplayPipeline{next: pipeline, payload: payload}, index, callReq)
}

type bodyReplayPipeline struct {
	next    nethttplibrary.Pipeline
	payload []byte
}

func (p *bodyReplayPipeline) Next(req *http.Request, index int) (*http.Response, error) {
	attempt := req.Clone(req.Context())
	attempt.Body = nethttplibrary.NopCloser(bytes.NewReader(p.payload))
	return p.next.Next(attempt, index)
}
