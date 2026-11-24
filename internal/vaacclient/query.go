package vaacclient

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

// Kind selects the fixed AA or CQ query. No user input becomes a column,
// filter expression, authority, resource, request header or URL.
type Kind int

const (
	AutoAttendant Kind = iota + 1
	CallQueue
)

const (
	rowLimit         = 4000
	maxQueries       = 17
	maxRows          = 20000
	maxResponseBytes = 8 << 20
	maxWindow        = 8 * time.Hour
)

const (
	// CQD's filter operand codes, confirmed against the reference queries.
	equal          = 0
	greaterOrEqual = 5
	lessOrEqual    = 7
)

type column struct {
	Name string `json:"DataModelName"`
}
type filter struct {
	column
	Value   string
	Operand int
}
type query struct {
	Filters              []filter
	Dimensions           []column
	Measurements         []column
	Parameters           struct{ UserAgent string }
	LimitResultRowsCount int
}

func (k Kind) build(from, to time.Time) (query, []string) {
	common := []string{"ConferenceId", "Duration", "EndTime", "FirstIsCaller", "FirstUPN", "PSTNCallType", "PSTNConnectivityType", "PSTNCallDuration", "Timestamp", "UserStartTimeUTC"}
	var fields, measures []string
	var has string
	switch k {
	case AutoAttendant:
		has = "HasAA"
		fields = []string{"AutoAttendantId", "AutoAttendantIdentity", "AutoAttendantCallFlow", "AutoAttendantCallResult", "AutoAttendantCallerActionCounts", "AutoAttendantChainDurationInSecs", "AutoAttendantChainIndex", "AutoAttendantChainStartTime", "AutoAttendantCount", "AutoAttendantDirectorySearchMethod", "AutoAttendantTransferAction"}
		measures = []string{"AvgAutoAttendantChainDurationSeconds", "AvgCallDuration", "TotalAudioStreamDuration", "TotalCallCount"}
	case CallQueue:
		has = "HasCQ"
		fields = []string{"DialogId", "SecondUPN", "CallQueueId", "CallQueueIdentity", "CallQueueDurationSeconds", "CallQueueAgentCount", "CallQueueAgentOptInCount", "CallQueueCallResult", "CallQueueFinalStateAction", "CallQueueTargetType"}
		measures = []string{"TotalCallCount"}
	}
	dimensions := append(common, fields...)
	q := query{
		Filters: []filter{
			{column{"EndTime"}, from.UTC().Format(time.RFC3339), greaterOrEqual},
			{column{"EndTime"}, to.UTC().Format(time.RFC3339), lessOrEqual},
			{column{has}, "True", equal},
		},
		LimitResultRowsCount: rowLimit,
	}
	for _, name := range dimensions {
		q.Dimensions = append(q.Dimensions, column{name})
	}
	for _, name := range measures {
		q.Measurements = append(q.Measurements, column{name})
	}
	q.Parameters.UserAgent = "Power BI Desktop"
	return q, slices.Concat(dimensions, measures)
}

// Row contains only selected, named dimensions and measurements. Numbers
// remain json.Number to avoid rounding identifiers or inventing zero values.
type Row map[string]any

// Fetch drains an EndTime interval for one stream. VAAC's reference request
// has no page cursor. A saturated response is not complete: split it by time
// and retry, or fail without returning partial rows when the budget is spent.
func (c *Client) Fetch(ctx context.Context, kind Kind, from, to time.Time) ([]Row, error) {
	rows, _, err := c.FetchPrefix(ctx, kind, from, to)
	if err != nil {
		return nil, err
	}
	return rows, nil
}

// FetchPrefix returns rows only from the contiguous, complete prefix of an
// EndTime interval, together with its inclusive end. An error means the rest
// was not read; a zero end means no complete prefix. All subqueries share the
// same per-stream request and row budgets, including saturated attempts in the
// request budget. The caller may commit the complete prefix and retry at its end.
func (c *Client) FetchPrefix(ctx context.Context, kind Kind, from, to time.Time) ([]Row, time.Time, error) {
	if kind != AutoAttendant && kind != CallQueue {
		return nil, time.Time{}, errors.New("invalid VAAC stream")
	}
	if from.IsZero() || to.Before(from) || to.Sub(from) > maxWindow {
		return nil, time.Time{}, errors.New("invalid VAAC query window")
	}
	from, to = from.Truncate(time.Second), to.Truncate(time.Second)
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	token, err := c.accessToken(ctx)
	if err != nil {
		return nil, time.Time{}, err
	}
	var rows []Row
	var through time.Time
	budget := maxQueries
	var fill func(time.Time, time.Time) error
	fill = func(lo, hi time.Time) error {
		if budget == 0 {
			return errors.New("VAAC query window exceeded request limit")
		}
		budget--
		part, saturated, err := c.fetch(ctx, token, kind, lo, hi)
		if err != nil {
			return err
		}
		if saturated {
			if hi.Sub(lo) <= time.Second {
				return errors.New("VAAC query window saturated at second resolution")
			}
			mid := lo.Add(hi.Sub(lo) / 2).Truncate(time.Second)
			if err := fill(lo, mid); err != nil {
				return err
			}
			return fill(mid, hi) // inclusive bounds; the collector dedupes the shared second
		}
		if len(rows)+len(part) > maxRows {
			return errors.New("VAAC query window exceeded row limit")
		}
		rows = append(rows, part...)
		through = hi
		return nil
	}
	err = fill(from, to)
	var status statusError
	if errors.As(err, &status) && status.code == http.StatusUnauthorized {
		c.mu.Lock()
		if c.token == token {
			c.token = ""
		}
		c.mu.Unlock()
	}
	return rows, through, err
}

func (c *Client) fetch(ctx context.Context, token string, kind Kind, from, to time.Time) ([]Row, bool, error) {
	q, columns := kind.build(from, to)
	data, err := json.Marshal(q)
	if err != nil {
		return nil, false, errors.New("VAAC query encoding failed")
	}
	var zipped bytes.Buffer
	zw := gzip.NewWriter(&zipped)
	if _, err := zw.Write(data); err != nil {
		return nil, false, errors.New("VAAC query compression failed")
	}
	if err := zw.Close(); err != nil {
		return nil, false, errors.New("VAAC query compression failed")
	}
	queryString := url.Values{"query": {base64.StdEncoding.EncodeToString(zipped.Bytes())}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, analytics+"?"+queryString.Encode(), nil)
	if err != nil {
		return nil, false, errors.New("VAAC analytics request could not be built")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := c.send(req, "analytics")
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	data, err = readBounded(resp.Body, maxResponseBytes)
	if err != nil {
		return nil, false, err
	}
	if strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") || bytes.HasPrefix(data, []byte{0x1f, 0x8b}) {
		zr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, false, errors.New("VAAC analytics response has invalid compression")
		}
		defer zr.Close()
		data, err = readBounded(zr, maxResponseBytes)
		if err != nil {
			return nil, false, err
		}
	}
	var payload struct {
		DataResult [][]any `json:"dataResult"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if dec.Decode(&payload) != nil || dec.Decode(new(any)) != io.EOF || payload.DataResult == nil {
		return nil, false, errors.New("VAAC analytics response is malformed")
	}
	if len(payload.DataResult) >= rowLimit {
		return nil, true, nil
	}
	rows := make([]Row, 0, len(payload.DataResult))
	for _, values := range payload.DataResult {
		if len(values) != len(columns) {
			return nil, false, errors.New("VAAC analytics response has a column mismatch")
		}
		row := make(Row, len(columns))
		for i, name := range columns {
			row[name] = values[i]
		}
		rows = append(rows, row)
	}
	return rows, false, nil
}
