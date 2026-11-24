package callrecords

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/rknightion/graph2otel/internal/collectors"
)

// docs-derived from Graph v1.0, not a captured tenant response:
// https://learn.microsoft.com/graph/api/callrecords-cloudcommunications-list-callrecords
// https://learn.microsoft.com/graph/api/callrecords-callrecord-get
// https://learn.microsoft.com/graph/api/callrecords-callrecord-list-participants_v2
// https://learn.microsoft.com/graph/api/callrecords-callrecord-list-sessions
const (
	path         = "/communications/callRecords"
	absolutePath = "https://graph.microsoft.com/v1.0" + path
	// Bound all auxiliary continuation requests for a single call together,
	// including continuations nested inside the sessions continuation pages.
	maxContinuationPages = 128
	maxCallBytes         = 32 << 20 // expanded detail plus all auxiliary JSON for one call
	listPageSize         = 60
	participantPageSize  = 130
)

type listRow struct {
	ID      string      `json:"id"`
	Version json.Number `json:"version"`
	Start   string      `json:"startDateTime"`
}

// The relationship tags spell the OData annotation separator as \u0040 so
// the source does not look like a mailbox. The decoded tag uses a literal @.
type detail struct {
	listRow
	End          string          `json:"endDateTime"`
	Type         string          `json:"type"`
	JoinWebURL   string          `json:"joinWebUrl"`
	Modalities   []string        `json:"modalities"`
	Organizer    *participant    `json:"organizer_v2"`
	Sessions     json.RawMessage `json:"sessions"`
	SessionsNext string          `json:"sessions\u0040odata.nextLink"`
	wireBytes    int
}

type session struct {
	ID           string          `json:"id"`
	Caller       endpoint        `json:"caller"`
	Callee       endpoint        `json:"callee"`
	Failure      *Failure        `json:"failureInfo"`
	Segments     json.RawMessage `json:"segments"`
	SegmentsNext string          `json:"segments\u0040odata.nextLink"`
}

type segment struct {
	ID      string   `json:"id"`
	Start   string   `json:"startDateTime"`
	End     string   `json:"endDateTime"`
	Caller  endpoint `json:"caller"`
	Callee  endpoint `json:"callee"`
	Failure *Failure `json:"failureInfo"`
	Media   []media  `json:"media"`
}

type media struct {
	Label         string       `json:"label"`
	CallerNetwork Network      `json:"callerNetwork"`
	CalleeNetwork Network      `json:"calleeNetwork"`
	CallerDevice  Device       `json:"callerDevice"`
	CalleeDevice  Device       `json:"calleeDevice"`
	Streams       []streamWire `json:"streams"`
}

type streamWire struct {
	StreamMetrics
	ID                        string `json:"streamId"`
	Direction                 string `json:"streamDirection"`
	Start                     string `json:"startDateTime"`
	End                       string `json:"endDateTime"`
	AverageRTT                string `json:"averageRoundTripTime"`
	MaxRTT                    string `json:"maxRoundTripTime"`
	AverageJitter             string `json:"averageJitter"`
	MaxJitter                 string `json:"maxJitter"`
	AverageAudioNetworkJitter string `json:"averageAudioNetworkJitter"`
	MaxAudioNetworkJitter     string `json:"maxAudioNetworkJitter"`
}

type endpoint struct {
	Identity Identity  `json:"associatedIdentity"`
	Agent    Agent     `json:"userAgent"`
	Feedback *Feedback `json:"feedback"`
	Name     string    `json:"name"`
}

type participant struct {
	ID         string      `json:"id"`
	Identities identitySet `json:"identity"`
}

type identitySet struct {
	User                *Identity `json:"user"`
	OnPremises          *Identity `json:"onPremises"`
	Guest               *Identity `json:"guest"`
	Phone               *Identity `json:"phone"`
	Application         *Identity `json:"application"`
	ApplicationInstance *Identity `json:"applicationInstance"`
	Device              *Identity `json:"device"`
	ACSUser             *Identity `json:"azureCommunicationServicesUser"`
	Asserted            *Identity `json:"assertedIdentity"`
}

type page[T any] struct {
	Value []T    `json:"value"`
	Next  string `json:"@odata.nextLink"`
}

func getPage[T any](ctx context.Context, g collectors.GraphClient, address string, headers map[string]string, budget *int) (page[T], error) {
	var p page[T]
	b, err := g.RawGetWithHeaders(ctx, address, headers)
	if err != nil {
		return p, err
	}
	if budget != nil {
		*budget -= len(b)
		if *budget < 0 {
			return p, errors.New("auxiliary byte budget exceeded for Teams call")
		}
	}
	if err := json.Unmarshal(b, &p); err != nil {
		return p, err
	}
	if p.Value == nil {
		return p, errors.New("missing collection value")
	}
	return p, nil
}

type listFetcher struct{ graph collectors.GraphClient }

func (f listFetcher) FetchPage(ctx context.Context, pageURL string) ([]map[string]any, string, error) {
	p, err := getPage[listRow](ctx, f.graph, pageURL, pagePreference(listPageSize), nil)
	if err != nil {
		return nil, "", err
	}
	if len(p.Value) > listPageSize {
		return nil, "", errors.New("requested page size exceeded for Teams call list")
	}
	rows := make([]map[string]any, 0, len(p.Value))
	for _, r := range p.Value {
		version, _ := r.Version.Int64() // an absent hint just means fetch detail
		rows = append(rows, map[string]any{"id": r.ID, "version": version, "startDateTime": r.Start})
	}
	return rows, p.Next, nil
}

// traversal shares one cap and cycle check across participants, sessions and
// segments. Graph's full continuation URL goes straight to the Graph client;
// it is never reconstructed or given fresh query parameters.
type traversal struct {
	seen      map[string]struct{}
	remaining int
}

func pagePreference(size int) map[string]string {
	if size == 0 {
		return nil
	}
	return map[string]string{"Prefer": fmt.Sprintf("odata.maxpagesize=%d", size)}
}

func drain[T any](ctx context.Context, g collectors.GraphClient, walk *traversal, first string, pageSize int, dst *[]T) error {
	headers := pagePreference(pageSize)
	for address := first; address != ""; {
		if _, ok := walk.seen[address]; ok {
			return errors.New("repeated Teams continuation URL")
		}
		if len(walk.seen) >= maxContinuationPages {
			return fmt.Errorf("auxiliary collection page limit of %d exceeded for Teams call", maxContinuationPages)
		}
		walk.seen[address] = struct{}{}
		p, err := getPage[T](ctx, g, address, headers, &walk.remaining)
		if err != nil {
			return err
		}
		if pageSize > 0 && len(p.Value) > pageSize {
			return errors.New("requested page size exceeded for Teams auxiliary collection")
		}
		*dst = append(*dst, p.Value...)
		address = p.Next
	}
	return nil
}

func getDetail(ctx context.Context, g collectors.GraphClient, id string) (detail, error) {
	var d detail
	address := absolutePath + "/" + url.PathEscape(id)
	b, err := g.RawGet(ctx, address+"?$expand=sessions($expand=segments)")
	if err != nil {
		return d, err
	}
	if len(b) > maxCallBytes {
		return d, errors.New("byte budget exceeded for Teams call detail")
	}
	if err := json.Unmarshal(b, &d); err != nil {
		return d, err
	}
	d.wireBytes = len(b)
	return d, nil
}

type hydratedSession struct {
	session
	segments []segment
}

func hydrate(ctx context.Context, g collectors.GraphClient, d detail) ([]hydratedSession, []participant, error) {
	walk := &traversal{seen: make(map[string]struct{}), remaining: maxCallBytes - d.wireBytes}
	var sessions []session
	if err := expanded(d.Sessions, d.SessionsNext, &sessions); err != nil {
		return nil, nil, fmt.Errorf("sessions: %w", err)
	}
	if err := drain(ctx, g, walk, d.SessionsNext, 0, &sessions); err != nil {
		return nil, nil, fmt.Errorf("sessions: %w", err)
	}
	hydrated := make([]hydratedSession, 0, len(sessions))
	for _, s := range sessions {
		h := hydratedSession{session: s}
		if err := expanded(s.Segments, s.SegmentsNext, &h.segments); err != nil {
			return nil, nil, fmt.Errorf("segments: %w", err)
		}
		if err := drain(ctx, g, walk, s.SegmentsNext, 0, &h.segments); err != nil {
			return nil, nil, fmt.Errorf("segments: %w", err)
		}
		hydrated = append(hydrated, h)
	}
	var participants []participant
	address := absolutePath + "/" + url.PathEscape(d.ID) + "/participants_v2"
	if err := drain(ctx, g, walk, address, participantPageSize, &participants); err != nil {
		return nil, nil, fmt.Errorf("participants_v2: %w", err)
	}
	return hydrated, participants, nil
}

func expanded[T any](raw json.RawMessage, next string, dst *[]T) error {
	if len(raw) == 0 {
		if next != "" {
			return nil
		}
		// An explicit null is documented for a nullable expansion. An omitted
		// relationship can mean the service did not perform the requested GET.
		return errors.New("expected expanded collection was absent")
	}
	return json.Unmarshal(raw, dst)
}

func parseTime(raw string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, raw)
	return t
}
