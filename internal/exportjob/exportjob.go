// Package exportjob implements the generic Intune reports export-job
// subsystem (#17): the async create → poll → download → unzip → parse
// pipeline every export-based report collector (app install status,
// feature-update device states, enrollment failures, certificate inventory,
// Defender agents, ...) builds on. Most fleet-wide Intune report data is only
// available this way — per-device entity walks blow the throttling budget on
// a large fleet.
//
// The flow: POST /deviceManagement/reports/exportJobs to create a job, poll
// GET .../exportJobs/{id} with exponential backoff to a terminal status
// (completed|failed), download the pre-signed SAS-url ZIP before it expires,
// and parse its single CSV or JSON entry into Rows. The whole flow shares one
// 48-req/min-per-app rate budget (graphclient's WorkloadIntuneExport) — every
// poll counts against it, which is why backoff matters here more than on a
// typical paged endpoint.
//
// This file is the frozen cross-package seam for M5
// (docs/superpowers/plans/m5-export-seam.md): the report collectors in #37/
// #38/#40/#41/#42 depend on Runner, Request, Row, and the two sentinel
// errors. Do not change a signature here without treating it as a seam
// change across every consumer.
package exportjob

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/rknightion/graph2otel/internal/telemetry"
)

// Default tuning applied by Options.withDefaults when the corresponding
// field is left zero.
const (
	defaultBaseURL     = "https://graph.microsoft.com/v1.0"
	defaultPollInitial = 3 * time.Second
	defaultPollMax     = 45 * time.Second
)

// Format selects the export job's payload encoding.
type Format string

const (
	// FormatCSV is the export API's default when Request.Format is left "".
	FormatCSV  Format = "csv"
	FormatJSON Format = "json"
)

// Request is one export-job spec.
type Request struct {
	// ReportName is the export report catalog name, e.g.
	// "DeviceInstallStatusByApp". Report-specific; see Microsoft's
	// available-reports reference.
	ReportName string
	// Select is the list of columns to export. REQUIRED and must be
	// non-empty: Microsoft warns the default column set can change without
	// notice, so every caller must pin its own columns explicitly. An empty
	// Select is a programming error, caught by Export before any network
	// call.
	Select []string
	// Filter is a report-specific DSL string, e.g. "(OwnerType eq '1')" —
	// NOT an OData $filter expression. Optional; only specific columns are
	// valid per report.
	Filter string
	// Format selects csv or json; "" defaults to FormatCSV.
	Format Format
	// LocalizationType is "LocalizedValuesAsAdditionalColumn" or
	// "ReplaceLocalizableValues"; "" omits the field from the request body
	// (some legacy reports ignore it entirely).
	LocalizationType string
}

// Row is one parsed record: column/field name -> string value.
type Row map[string]string

// Runner is what report collectors depend on (fakeable in tests). *Client
// implements it.
type Runner interface {
	Export(ctx context.Context, req Request, e telemetry.Emitter) ([]Row, error)
}

// Poster is the Graph seam this package builds on: create (RawPost) + poll
// (RawGetWithHeaders) through the instrumented, rate-limited transport.
// Satisfied by *graphclient.Client.
type Poster interface {
	RawPost(ctx context.Context, url string, body []byte, headers map[string]string) ([]byte, error)
	RawGetWithHeaders(ctx context.Context, url string, headers map[string]string) ([]byte, error)
}

// Downloader fetches the pre-signed SAS url returned by a completed job.
// This is an Azure Blob Storage url, NOT a Graph call — no bearer token is
// sent or accepted. See DefaultDownloader for the production implementation;
// injectable for tests.
type Downloader interface {
	Download(ctx context.Context, sasURL string) ([]byte, error)
}

// Options tunes a Client. Every field defaults sensibly when left zero; see
// withDefaults.
type Options struct {
	// BaseURL is the Graph service root the export endpoints hang off of.
	// Defaults to "https://graph.microsoft.com/v1.0".
	BaseURL string
	// PollInitial is the first poll backoff delay. Defaults to 3s.
	PollInitial time.Duration
	// PollMax is the backoff ceiling; delay doubles from PollInitial up to
	// this cap. Defaults to 45s.
	PollMax time.Duration
	// Now returns the current time; defaults to time.Now. Injectable so
	// tests can control SAS-expiry evaluation without real clock skew.
	Now func() time.Time
	// Sleep waits d, honoring ctx cancellation; defaults to a real,
	// ctx-aware sleep. Tests inject a no-op so backoff tests don't take
	// wall-clock time.
	Sleep func(ctx context.Context, d time.Duration) error
}

func (o Options) withDefaults() Options {
	if o.BaseURL == "" {
		o.BaseURL = defaultBaseURL
	}
	if o.PollInitial <= 0 {
		o.PollInitial = defaultPollInitial
	}
	if o.PollMax <= 0 {
		o.PollMax = defaultPollMax
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Sleep == nil {
		o.Sleep = ctxSleep
	}
	return o
}

// ctxSleep is Options.Sleep's production default: waits d unless ctx is
// canceled first.
func ctxSleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Distinct, classifiable errors. Both are returned wrapped (errors.Is
// applies).
var (
	// ErrJobFailed means the export job itself reported status "failed".
	// Not retryable by re-polling the same job id.
	ErrJobFailed = errors.New("exportjob: job reported status failed")
	// ErrSASExpired means the job completed but its pre-signed download url
	// expired before Export got to it. Retryable: re-create the job.
	ErrSASExpired = errors.New("exportjob: SAS url expired before download")
)

// Client implements Runner over a real Poster + Downloader.
type Client struct {
	graph Poster
	dl    Downloader
	opts  Options
}

// New returns a Client. graph is typically *graphclient.Client; dl is
// typically DefaultDownloader().
func New(graph Poster, dl Downloader, opts Options) *Client {
	return &Client{graph: graph, dl: dl, opts: opts.withDefaults()}
}

// exportJobBody is the create request's JSON body.
type exportJobBody struct {
	ReportName       string   `json:"reportName"`
	Select           []string `json:"select"`
	Filter           string   `json:"filter,omitempty"`
	Format           string   `json:"format"`
	LocalizationType string   `json:"localizationType,omitempty"`
}

// exportJobResponse is the shape of both the create response and every poll
// response; only the fields relevant to a given stage are populated.
type exportJobResponse struct {
	ID                 string `json:"id"`
	Status             string `json:"status"`
	URL                string `json:"url"`
	ExpirationDateTime string `json:"expirationDateTime"`
}

// Export runs the full create → poll → download → parse flow for req,
// emitting the graph2otel.export.* self-observability metrics through e.
func (c *Client) Export(ctx context.Context, req Request, e telemetry.Emitter) ([]Row, error) {
	if len(req.Select) == 0 {
		return nil, fmt.Errorf("exportjob: %s: Request.Select must be non-empty (Microsoft: default export columns can change without notice)", req.ReportName)
	}

	format := req.Format
	if format == "" {
		format = FormatCSV
	}

	start := c.opts.Now()

	id, err := c.create(ctx, req, format)
	if err != nil {
		return nil, fmt.Errorf("exportjob: %s: create: %w", req.ReportName, err)
	}

	jr, pollCount, err := c.poll(ctx, req.ReportName, id)
	if err != nil {
		if errors.Is(err, ErrJobFailed) {
			c.emitTerminal(e, req.ReportName, "failed", pollCount, c.opts.Now().Sub(start), 0)
		}
		return nil, err
	}

	expiry, perr := time.Parse(time.RFC3339, jr.ExpirationDateTime)
	if perr != nil {
		return nil, fmt.Errorf("exportjob: %s: parse expirationDateTime %q: %w", req.ReportName, jr.ExpirationDateTime, perr)
	}
	if !c.opts.Now().Before(expiry) {
		return nil, fmt.Errorf("exportjob: %s: %w", req.ReportName, ErrSASExpired)
	}

	zipBytes, err := c.dl.Download(ctx, jr.URL)
	if err != nil {
		return nil, fmt.Errorf("exportjob: %s: download: %w", req.ReportName, err)
	}

	rows, err := parseZIPPayload(zipBytes, format)
	if err != nil {
		return nil, fmt.Errorf("exportjob: %s: parse: %w", req.ReportName, err)
	}

	c.emitTerminal(e, req.ReportName, "completed", pollCount, c.opts.Now().Sub(start), len(zipBytes))
	return rows, nil
}

// create POSTs the export-job spec and returns the new job's id.
func (c *Client) create(ctx context.Context, req Request, format Format) (string, error) {
	body := exportJobBody{
		ReportName:       req.ReportName,
		Select:           req.Select,
		Filter:           req.Filter,
		Format:           string(format),
		LocalizationType: req.LocalizationType,
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("marshal request body: %w", err)
	}

	respBody, err := c.graph.RawPost(ctx, c.opts.BaseURL+"/deviceManagement/reports/exportJobs", raw, nil)
	if err != nil {
		return "", err
	}

	var jr exportJobResponse
	if err := json.Unmarshal(respBody, &jr); err != nil {
		return "", fmt.Errorf("decode create response: %w", err)
	}
	if jr.ID == "" {
		return "", fmt.Errorf("create response missing id")
	}
	return jr.ID, nil
}

// poll polls the export job at id to a terminal status, backing off from
// PollInitial to PollMax between attempts. It returns the terminal response
// (only populated on "completed"), the number of polls it took, and
// ErrJobFailed wrapped when the job reports "failed".
func (c *Client) poll(ctx context.Context, reportName, id string) (exportJobResponse, int, error) {
	pollURL := c.opts.BaseURL + "/deviceManagement/reports/exportJobs/" + id
	delay := c.opts.PollInitial
	pollCount := 0

	for {
		if err := ctx.Err(); err != nil {
			return exportJobResponse{}, pollCount, err
		}

		body, err := c.graph.RawGetWithHeaders(ctx, pollURL, nil)
		if err != nil {
			return exportJobResponse{}, pollCount, fmt.Errorf("exportjob: %s: poll: %w", reportName, err)
		}
		pollCount++

		var jr exportJobResponse
		if err := json.Unmarshal(body, &jr); err != nil {
			return exportJobResponse{}, pollCount, fmt.Errorf("exportjob: %s: decode poll response: %w", reportName, err)
		}

		switch jr.Status {
		case "completed":
			return jr, pollCount, nil
		case "failed":
			return exportJobResponse{}, pollCount, fmt.Errorf("exportjob: %s: %w", reportName, ErrJobFailed)
		default:
			if err := c.opts.Sleep(ctx, delay); err != nil {
				return exportJobResponse{}, pollCount, err
			}
			delay *= 2
			if delay > c.opts.PollMax {
				delay = c.opts.PollMax
			}
		}
	}
}

// emitTerminal records the graph2otel.export.* self-obs metrics for one
// Export call's terminal outcome. bytesLen is 0 (and no bytes gauge is
// emitted) when result != "completed".
func (c *Client) emitTerminal(e telemetry.Emitter, reportName, result string, pollCount int, duration time.Duration, bytesLen int) {
	attrs := telemetry.Attrs{"report_name": reportName}
	e.Counter("graph2otel.export.jobs", "{job}", "Intune export jobs by terminal result.", 1,
		telemetry.Attrs{"report_name": reportName, "result": result})
	e.Gauge("graph2otel.export.poll_count", "{poll}", "Number of status polls the last export job needed to reach a terminal state.", float64(pollCount), attrs)
	e.Gauge("graph2otel.export.duration_seconds", "s", "Wall-clock duration of the last export job from create to terminal state.", duration.Seconds(), attrs)
	if result == "completed" {
		e.Gauge("graph2otel.export.bytes", "By", "Size in bytes of the last downloaded export ZIP.", float64(bytesLen), attrs)
	}
}

// parseZIPPayload opens the single-entry ZIP zipBytes and parses that entry
// as CSV or JSON per format.
func parseZIPPayload(zipBytes []byte, format Format) ([]Row, error) {
	zr, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		return nil, fmt.Errorf("open zip: %w", err)
	}
	if len(zr.File) == 0 {
		return nil, fmt.Errorf("zip has no entries")
	}

	f := zr.File[0]
	rc, err := f.Open()
	if err != nil {
		return nil, fmt.Errorf("open zip entry %s: %w", f.Name, err)
	}
	defer rc.Close()

	data, err := io.ReadAll(rc)
	if err != nil {
		return nil, fmt.Errorf("read zip entry %s: %w", f.Name, err)
	}

	if format == FormatJSON {
		return parseJSONRows(data)
	}
	return parseCSVRows(data)
}

// parseCSVRows parses data as CSV: the first row is the header, and every
// subsequent row becomes a Row keyed by that header.
func parseCSVRows(data []byte) ([]Row, error) {
	r := csv.NewReader(bytes.NewReader(data))
	records, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("parse csv: %w", err)
	}
	if len(records) == 0 {
		return []Row{}, nil
	}

	header := records[0]
	rows := make([]Row, 0, len(records)-1)
	for _, rec := range records[1:] {
		row := make(Row, len(header))
		for i, h := range header {
			if i < len(rec) {
				row[h] = rec[i]
			}
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// parseJSONRows parses data as either a bare JSON array of objects or a
// {"values": [...]} wrapper, per the export API's documented JSON shape.
// Numbers are decoded via json.Number so large IDs round-trip exactly,
// rather than through float64 (which would lose precision on Row's string
// values).
func parseJSONRows(data []byte) ([]Row, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()

	trimmed := bytes.TrimSpace(data)
	var objs []map[string]any
	if len(trimmed) > 0 && trimmed[0] == '[' {
		if err := dec.Decode(&objs); err != nil {
			return nil, fmt.Errorf("parse json array: %w", err)
		}
	} else {
		var wrapper struct {
			Values []map[string]any `json:"values"`
		}
		if err := dec.Decode(&wrapper); err != nil {
			return nil, fmt.Errorf("parse json object: %w", err)
		}
		objs = wrapper.Values
	}

	rows := make([]Row, 0, len(objs))
	for _, obj := range objs {
		row := make(Row, len(obj))
		for k, v := range obj {
			row[k] = jsonValueToString(v)
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// jsonValueToString renders one decoded JSON value (string, json.Number,
// bool, nil, or a nested value) as a Row's string value.
func jsonValueToString(v any) string {
	switch val := v.(type) {
	case nil:
		return ""
	case string:
		return val
	case json.Number:
		return val.String()
	case bool:
		return strconv.FormatBool(val)
	default:
		return fmt.Sprint(val)
	}
}
