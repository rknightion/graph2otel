package collectors

import (
	"log/slog"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/o365activityclient"
)

// O365Deps is everything an O365Factory needs to construct an Office 365
// Management Activity API collector for one tenant (#100). It is the fourth
// construction path alongside Deps (snapshot), WindowDeps (logpipeline /
// jobpipeline) and BlobDeps (Azure Storage).
//
// It exists because none of the other three can carry an
// *o365activityclient.Client: the Management Activity API is a second
// first-party API with its own audience (https://manage.office.com), its own
// per-tenant throttle ceiling and its own subscribe→list-content→fetch-blob
// model. It is not Graph, so a WindowDeps.Fetcher cannot reach it; it is not
// Azure Storage, so BlobDeps.Source cannot either.
//
// Like BlobDeps it is deliberately small: this API needs no Graph client, no
// page fetcher and no license capabilities. Its access is gated by the
// ActivityFeed.Read application role, which either the token carries or it does
// not — there is no license tier to detect.
type O365Deps struct {
	// Client drives the tenant's Management Activity API. Built once per tenant
	// by the composition root over the tenant's own credential, and nil when the
	// tenant has configured no O365 activity content types — in which case no
	// O365 collectors are constructed at all, exactly as an unset
	// blob_ingest.account_url constructs no blob collectors.
	Client *o365activityclient.Client
	// ContentTypes are the Management Activity API content types this tenant
	// subscribes to, from config. Empty means "use the collector's own default"
	// — which is Audit.Exchange + Audit.SharePoint.
	//
	// This is per-tenant config rather than a constant because the choice has
	// real consequences and no default is right for everyone. The API has NO
	// server-side filtering, so a content type is all-or-nothing: subscribing
	// means fetching every record it carries. Measured on m7kni over 23h,
	// Audit.General is 4,035 records of which 3,865 are Endpoint DLP and 3 are
	// Teams — so a tenant that wants Teams admin activity pays for the whole
	// catch-all to get it.
	//
	// Audit.General is therefore NOT a default. Not because of volume cost per
	// se, but because graph2otel is deployed by operators who pay per GB
	// downstream, and defaulting them into a workload they never asked for is
	// the wrong way round. A tenant that wants it — a SIEM feed, where Endpoint
	// DLP file activity with hashes is a feature and not noise — opts in here,
	// and then EVERY record is shipped (#112: fetching per-entity rows and
	// discarding them is a bug, so there is no record-type include-list).
	//
	// Audit.AzureActiveDirectory is also not a default: it carries UserLoggedIn
	// and directory-audit records that entra.signins.interactive and
	// entra.directory_audits already emit, and both of those are logs-only
	// collectors, so subscribing here duplicates them into the same pipeline.
	ContentTypes []o365activityclient.ContentType
	// TenantID is the tenant this collector instance serves. It is both the
	// tenant component of the checkpoint key and the tenant GUID in the API's
	// root URL.
	TenantID string
	// Logger is the process logger, for per-content-type diagnostics.
	Logger *slog.Logger
	// Store persists each collector's checkpoint (watermark, overlap, seen
	// content IDs and seen record IDs) across restarts. The same
	// checkpoint.Store every other engine uses; the cursor kinds are namespaced
	// apart on disk.
	Store *checkpoint.Store
}

// O365Factory constructs one Management Activity API collector for a tenant.
// Registered from a collector subpackage's init() via RegisterO365; the
// composition root calls it once per tenant that has O365 activity configured,
// then gates the result through the same config gate as every other collector.
//
// It returns a RegisteredWindow — reusing the window path rather than inventing
// a parallel one — because an o365pipeline collector genuinely is a
// WindowCollector: its progress is a time watermark over contentCreated, so the
// scheduler's [from, to] contract is the exact fit. InitialLookback and
// MaxWindow therefore live HERE, on the schedule bounds the scheduler honors,
// and NOT on o365pipeline.EndpointConfig: duplicating them would let the engine
// and the scheduler disagree about the same window, and the scheduler would win
// silently. This mirrors logpipeline, where EndpointConfig carries no lookback
// for the same reason.
//
// Note MaxWindow interacts with a hard API bound: /subscriptions/content
// rejects a range over 24h (AF20055) and — worse — may return HTTP 200 with
// SILENTLY PARTIAL results for a wider one. o365activityclient chunks
// internally so a wider MaxWindow stays correct, but keeping MaxWindow at or
// under 24h keeps one tick to one request per content type.
type O365Factory func(O365Deps) RegisteredWindow

// registeredO365 accumulates every O365-collector factory. Populated only from
// subpackage init() functions (single-threaded package initialization), so it
// needs no synchronization.
var registeredO365 []O365Factory

// RegisterO365 adds an O365-collector factory. Call it from a collector
// subpackage's init(). Registration order is preserved by O365All().
func RegisterO365(f O365Factory) { registeredO365 = append(registeredO365, f) }

// O365All returns every registered O365-collector factory in registration
// order. The composition root calls each one per tenant with O365 activity
// configured.
func O365All() []O365Factory { return registeredO365 }
