// Package hardwareinventory is the Intune per-device HARDWARE inventory
// collector (BETA): the `hardwareInformation` complex type on a managedDevice —
// disk capacity, TPM chip identity, firmware/BIOS version, Windows Device Guard
// state, OS edition, licensing status, battery, wired IPs and mobile/cellular
// identity.
//
// # Why the fetch shape is what it is (live-measured 2026-07-21, #199)
//
// `hardwareInformation` exists ONLY on the beta managedDevice type — the v1.0
// type does not declare it at all, which is why this collector is Experimental —
// and it materializes only on a SINGLE-ENTITY GET:
//
//	GET  /beta/deviceManagement/managedDevices?$select=hardwareInformation      -> 200, a 40-key STUB, 6-8 fields populated
//	GET  /beta/deviceManagement/managedDevices/{id}?$select=hardwareInformation -> 200, 16-21 fields populated
//	GET  /beta/deviceManagement/managedDevices?$expand=hardwareInformation      -> 400, the property is not expandable
//	GET  /beta/deviceManagement/managedDevices?$filter=id eq '...'              -> 400, filtering on id is unsupported here
//
// So there is no bulk form. The earlier verdict that this data "does not exist on
// this tenant" came from reading the LIST stub's nulls; it was a request-shape
// artifact, not a fact about the tenant.
//
// The N+1 that implies is paid through `POST /beta/$batch`, live-verified
// working here: the whole ten-device fleet in ONE call, every sub-response 200
// and fully populated. Chunked at Graph's documented ceiling of 20 sub-requests
// (see batchChunkSize for that one's evidence class), one cycle costs
// 1 + ceil(N/20) requests — the most expensive fetch shape in this repo, and the
// reason DefaultInterval is 24h rather than the 1h every other device-posture
// snapshot collector uses. Intune itself refreshes device hardware inventory on a
// multi-day cycle, so a shorter interval would spend $batch quota re-fetching
// byte-identical data.
//
// # Relationship to intune.devices — the division of data
//
// intune.devices already emits a per-device twin carrying id, deviceName,
// serialNumber, userPrincipalName, operatingSystem, osVersion, model,
// manufacturer, wiFiMacAddress, complianceState and isEncrypted. None of that is
// the point of this collector and it is deliberately NOT re-emitted here. Device
// id and deviceName ride the intune.device_hardware twin purely as the JOIN KEY
// back to intune.managed_device; manufacturer rides it because it is one of this
// collector's own gauge labels and every gauge dimension must be answerable from
// the twin. Everything else on the twin is data that exists on no other surface.
//
// # Wire traps (all live-observed on the m7kni fleet, 2026-07-21)
//
//   - `batteryHealthPercentage` and `batteryChargeCycles` read 0 on EVERY device,
//     including two working MacBook Pros. Zero battery health on a working laptop
//     is not a measurement, it is "not reported" — so 0 omits the attribute. The
//     same treatment is deliberately NOT applied to `batteryLevelPercentage`,
//     where 100.0 is live and plausible.
//   - `totalStorageSpace` reads 0 on the Defender-managed Linux host, which
//     plainly has a disk. Same reasoning: total==0 means "not reported", so that
//     device contributes no storage series and no storage twin attribute. A free
//     space of 0 with a non-zero total IS a real reading (a full disk) and is
//     emitted.
//   - The three `deviceGuard*` fields report Windows-only values on macOS, iOS and
//     Linux (`mbp14` returns meetHardwareRequirements / running / running). They
//     are emitted VERBATIM — not filtered by OS and not "corrected" (#142). They
//     are NOT trustworthy on a non-Windows device and must not be read as a macOS
//     or Linux security posture.
//   - `tpmSpecificationVersion` is a comma-joined TRIPLE ("2.0, 0, 1.16"), not a
//     plain version number. It is emitted verbatim and never parsed. It is bounded
//     in practice (a handful of TPM revisions per fleet), which is what makes it
//     safe as a gauge label — unlike `tpmVersion`, the chip's own firmware version,
//     which is per-entity and twin-only.
//   - `wiredIPv4Addresses` and `sharedDeviceCachedUsers` are JSON ARRAYS, often
//     `[]`. `sharedDeviceCachedUsers` is deliberately NOT mapped: it is empty on
//     every row available, and mapping a collection nobody has seen populated is
//     mapping against docs. The same applies to `deviceLicensingLastErrorCode` /
//     `deviceLicensingLastErrorDescription` (0/null fleet-wide) and to the fields
//     that are null on all ten devices (meid, batterySerialNumber, osBuildNumber,
//     ipAddressV4, subnetAddress, residentUsersCount, deviceFullQualifiedDomainName).
//   - `deviceLicensingStatus` is a STRING, and one live row carries "25" — Graph
//     stringifying an enum member it has no name for. It is decoded tolerantly
//     (string or bare number) so a tenant returning the other scalar shape cannot
//     fail the row.
//   - Nulls vary by platform: iOS/macOS/Linux populate a different subset than
//     Windows. Every attribute is omitted when its field is null/empty rather than
//     emitted blank.
//
// # Cardinality (#112/#114)
//
// The four gauges carry only bounded dimensions: the bucketed operating system
// (identical value space to intune.devices), manufacturer, the TPM specification
// triple, the two Device Guard states, and total/free. Storage BYTES, TPM chip
// version, wired IPs, IMEI/eSIM/phone number, product name and the device
// identity are per-entity and ride the intune.device_hardware twin — one record
// per device, every cycle, never dropped.
package hardwareinventory

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/graphclient"
	"github.com/rknightion/graph2otel/internal/preflight"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	collectorName = "intune.hardware_inventory"
	// devicesMetricName counts devices by the bounded (OS bucket, manufacturer)
	// pair. Each gauge below is its OWN metric name rather than another dimension
	// on this one, so a naive sum() over any single metric is the true device
	// count — the rule stated above countMetricName in intune/manageddevices.
	devicesMetricName = "intune.hardware_inventory.devices"
	// tpmMetricName counts devices by TPM specification version (verbatim triple).
	tpmMetricName = "intune.hardware_inventory.tpm_devices"
	// deviceGuardMetricName counts devices by the VBS + Credential Guard state pair.
	deviceGuardMetricName = "intune.hardware_inventory.device_guard_devices"
	// storageMetricName sums disk bytes per OS bucket, split total vs free.
	storageMetricName = "intune.hardware_inventory.storage_bytes"
	eventName         = "intune.device_hardware"
	// defaultBaseURL is the Graph BETA root — hardwareInformation is not on the
	// v1.0 managedDevice type at all. See the package doc.
	defaultBaseURL = "https://graph.microsoft.com/beta"
	// listPath enumerates the fleet's ids. deviceName rides along only so a
	// dropped $batch sub-response can be logged against a human name; every
	// emitted field comes from the per-device sub-response. No $top — GetAllValues
	// already asks for Graph's largest page via the Prefer header, and an
	// unverified $top is how a paged collector earns a 400
	// (docs/graph-api-gotchas.md).
	listPath = "/deviceManagement/managedDevices?$select=id,deviceName"
	// batchPath is the Graph JSON batching endpoint, POSTed to under the same beta
	// root so its sub-requests resolve against beta.
	batchPath = "/$batch"
	// devicePathFmt is one $batch sub-request URL. Sub-request URLs are
	// SERVICE-RELATIVE (no /beta prefix — the outer POST already selected the
	// version). The $select mirrors the live probe exactly.
	devicePathFmt = "/deviceManagement/managedDevices/%s?$select=id,deviceName,operatingSystem,hardwareInformation"
	// batchChunkSize is Graph's ceiling of 20 sub-requests per $batch call.
	// EVIDENCE CLASS: the live probe (2026-07-21) ran the whole ten-device m7kni
	// fleet in ONE call and got ten 200s — so $batch itself is live-measured, but
	// the 20 boundary is DOCS-ONLY and has not been driven to the edge on this
	// tenant. It is the conservative direction (a smaller chunk only costs
	// requests), so a wrong ceiling degrades cost, never correctness.
	batchChunkSize = 20
	// unknownValue keeps a bounded gauge dimension stable when a device omits one
	// of its wire values, rather than emitting an empty label.
	unknownValue = "unknown"
)

// batchPoster is the POST seam this collector needs on top of
// collectors.GraphClient, which is GET-only. *graphclient.Client satisfies it;
// the interface is declared locally (rather than widening GraphClient) because
// exactly one collector needs POST and widening the shared seam would force a
// RawPost stub into every collector fake in the repo.
type batchPoster interface {
	RawPost(ctx context.Context, url string, body []byte, headers map[string]string) ([]byte, error)
}

// batchRequest is the JSON batching envelope: up to batchChunkSize sub-requests.
type batchRequest struct {
	Requests []batchSubRequest `json:"requests"`
}

// batchSubRequest is one GET inside a batch. ID is a chunk-relative ordinal
// (deliberately not the device GUID: Graph documents no length bound for the
// field, and an ordinal is the shape every Graph example uses).
type batchSubRequest struct {
	ID     string `json:"id"`
	Method string `json:"method"`
	URL    string `json:"url"`
}

// batchResponse is the reply envelope. Graph does NOT guarantee the responses
// come back in request order, so they are correlated by ID.
type batchResponse struct {
	Responses []batchSubResponse `json:"responses"`
}

// batchSubResponse is one sub-response. A non-200 Status carries an OData error
// in Body instead of a device.
type batchSubResponse struct {
	ID     string          `json:"id"`
	Status int             `json:"status"`
	Body   json.RawMessage `json:"body"`
}

// Collector polls the beta managedDevices fleet for per-device hardware inventory.
type Collector struct {
	g collectors.GraphClient
	// poster is g asserted to batchPoster; nil when the injected client cannot
	// POST, which Collect reports as an error rather than emitting an empty fleet.
	poster  batchPoster
	baseURL string
	logger  *slog.Logger
}

// New builds the collector. A nil logger falls back to slog.Default().
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	c := &Collector{g: g, baseURL: defaultBaseURL, logger: logger}
	if p, ok := g.(batchPoster); ok {
		c.poster = p
	}
	return c
}

func (c *Collector) Name() string { return collectorName }

// DefaultInterval is 24h, not the 1h the other device-posture snapshot collectors
// use. Intune refreshes device hardware inventory on a multi-day cycle, so a
// shorter interval spends this collector's 1 + ceil(N/20) requests per cycle —
// the most expensive fetch shape in the repo — re-reading identical data. The
// interval IS the mitigation for the fetch shape.
func (c *Collector) DefaultInterval() time.Duration { return 24 * time.Hour }

// Experimental reports true: hardwareInformation exists only on the beta
// managedDevice type.
func (c *Collector) Experimental() bool { return true }

// RequiredPermissions declares the single read-only least-privilege scope. Both
// the list GET and every $batch sub-request are plain GETs; the $batch POST is a
// transport envelope, not a write.
func (c *Collector) RequiredPermissions() []string {
	return []string{"DeviceManagementManagedDevices.Read.All"}
}

// deviceRow is one $batch sub-response body: the managedDevice fields selected
// plus its hardware inventory.
type deviceRow struct {
	ID              string   `json:"id"`
	DeviceName      string   `json:"deviceName"`
	OperatingSystem string   `json:"operatingSystem"`
	Hardware        hardware `json:"hardwareInformation"`
}

// hardware is the beta `hardwareInformation` complex type, restricted to the
// fields live-observed populated on at least one device. See the package doc for
// what is deliberately not mapped and why.
type hardware struct {
	TotalStorageSpace int64 `json:"totalStorageSpace"`
	FreeStorageSpace  int64 `json:"freeStorageSpace"`

	Manufacturer            string `json:"manufacturer"`
	OperatingSystemLanguage string `json:"operatingSystemLanguage"`
	OperatingSystemEdition  string `json:"operatingSystemEdition"`
	// OperatingSystemProductType is Microsoft's numeric Windows product-type code
	// (4/48/72 live). Non-Windows devices report 0. Emitted verbatim: unlike a 0
	// battery health on a working laptop, a 0 here is not a self-contradictory
	// reading, and the project's default is to emit what was on the wire.
	OperatingSystemProductType  int64  `json:"operatingSystemProductType"`
	SystemManagementBIOSVersion string `json:"systemManagementBIOSVersion"`
	ProductName                 string `json:"productName"`

	TPMSpecificationVersion string `json:"tpmSpecificationVersion"`
	TPMManufacturer         string `json:"tpmManufacturer"`
	TPMVersion              string `json:"tpmVersion"`

	DeviceGuardHardwareRequirementState string `json:"deviceGuardVirtualizationBasedSecurityHardwareRequirementState"`
	DeviceGuardVBSState                 string `json:"deviceGuardVirtualizationBasedSecurityState"`
	DeviceGuardCredentialGuardState     string `json:"deviceGuardLocalSystemAuthorityCredentialGuardState"`

	IsSupervised   bool `json:"isSupervised"`
	IsSharedDevice bool `json:"isSharedDevice"`

	// BatteryLevelPercentage is a pointer: null (not reported) must be
	// distinguishable from a real 0% charge.
	BatteryLevelPercentage  *float64 `json:"batteryLevelPercentage"`
	BatteryHealthPercentage int64    `json:"batteryHealthPercentage"`
	BatteryChargeCycles     int64    `json:"batteryChargeCycles"`

	WiredIPv4Addresses []string `json:"wiredIPv4Addresses"`

	IMEI               string `json:"imei"`
	ESIMIdentifier     string `json:"esimIdentifier"`
	PhoneNumber        string `json:"phoneNumber"`
	SubscriberCarrier  string `json:"subscriberCarrier"`
	CellularTechnology string `json:"cellularTechnology"`

	// DeviceLicensingStatus is json.RawMessage so a bare number cannot fail the
	// row's decode — see scalarString.
	DeviceLicensingStatus json.RawMessage `json:"deviceLicensingStatus"`
}

// listEntry is one row of the id-listing page walk.
type listEntry struct {
	ID         string `json:"id"`
	DeviceName string `json:"deviceName"`
}

// Collect enumerates the fleet's device ids, fetches each device's
// hardwareInformation through chunked $batch calls, then emits the four bounded
// gauges and one twin per device.
//
// Failure model, deliberately asymmetric:
//
//   - A 403 on the fleet list is a graceful info-level skip (missing scope, or
//     Intune not licensed on this tenant), like every other Intune collector.
//   - A per-device sub-response failure (404 for a device deleted between the
//     list and the batch, 403 for one scoped away) skips that device with a
//     warning. It is individually rare and must not cost the other 19 in its chunk.
//   - A whole-$batch POST failure fails the collection and emits NOTHING. The
//     gauges are a fleet snapshot; publishing one that silently omits a chunk of
//     twenty would read on a dashboard as twenty devices vanishing. Nothing is
//     emitted until every chunk has been fetched.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	if c.poster == nil {
		return fmt.Errorf("%s: Graph client cannot POST, so the required $batch fetch is impossible", collectorName)
	}

	entries, err := c.listDevices(ctx)
	if err != nil {
		if isForbidden(err) {
			c.logger.Info("hardwareinventory: managedDevices forbidden (missing scope?); skipping",
				"collector", collectorName, "error", graphclient.FormatODataError(err))
			return nil
		}
		return fmt.Errorf("%s: list managed devices: %w", collectorName, err)
	}
	if len(entries) == 0 {
		return nil
	}

	rows, err := c.fetchHardware(ctx, entries)
	if err != nil {
		return err
	}

	c.emit(e, rows)
	return nil
}

// listDevices pages the fleet for ids (plus deviceName, for skip diagnostics).
func (c *Collector) listDevices(ctx context.Context) ([]listEntry, error) {
	raws, err := collectors.GetAllValues(ctx, c.g, c.baseURL+listPath, nil)
	if err != nil {
		return nil, err
	}
	out := make([]listEntry, 0, len(raws))
	for _, raw := range raws {
		var le listEntry
		if err := json.Unmarshal(raw, &le); err != nil {
			return nil, fmt.Errorf("decode managedDevice list element: %w", err)
		}
		if le.ID == "" {
			continue
		}
		out = append(out, le)
	}
	return out, nil
}

// fetchHardware runs the chunked $batch sweep and returns one deviceRow per
// device whose sub-response came back 200. Any chunk-level failure aborts.
func (c *Collector) fetchHardware(ctx context.Context, entries []listEntry) ([]deviceRow, error) {
	rows := make([]deviceRow, 0, len(entries))
	for start := 0; start < len(entries); start += batchChunkSize {
		end := min(start+batchChunkSize, len(entries))
		chunk := entries[start:end]

		req := batchRequest{Requests: make([]batchSubRequest, 0, len(chunk))}
		for i, entry := range chunk {
			req.Requests = append(req.Requests, batchSubRequest{
				ID:     fmt.Sprint(i),
				Method: "GET",
				URL:    fmt.Sprintf(devicePathFmt, entry.ID),
			})
		}
		body, err := json.Marshal(req)
		if err != nil {
			return nil, fmt.Errorf("%s: encode $batch request: %w", collectorName, err)
		}
		respBody, err := c.poster.RawPost(ctx, c.baseURL+batchPath, body, nil)
		if err != nil {
			return nil, fmt.Errorf("%s: $batch devices %d-%d: %w", collectorName, start, end-1, err)
		}
		var resp batchResponse
		if err := json.Unmarshal(respBody, &resp); err != nil {
			return nil, fmt.Errorf("%s: decode $batch response: %w", collectorName, err)
		}

		byID := make(map[string]batchSubResponse, len(resp.Responses))
		for _, sub := range resp.Responses {
			byID[sub.ID] = sub
		}
		for i, entry := range chunk {
			sub, ok := byID[fmt.Sprint(i)]
			if !ok {
				c.logger.Warn("hardwareinventory: no $batch sub-response for device; skipping",
					"collector", collectorName, "device_id", entry.ID, "device_name", entry.DeviceName)
				continue
			}
			if sub.Status != 200 {
				c.logger.Warn("hardwareinventory: device hardware sub-request failed; skipping device",
					"collector", collectorName, "device_id", entry.ID, "device_name", entry.DeviceName,
					"status", sub.Status, "body", string(sub.Body))
				continue
			}
			var row deviceRow
			if err := json.Unmarshal(sub.Body, &row); err != nil {
				c.logger.Warn("hardwareinventory: undecodable device hardware body; skipping device",
					"collector", collectorName, "device_id", entry.ID, "device_name", entry.DeviceName, "error", err)
				continue
			}
			if row.ID == "" {
				row.ID = entry.ID
			}
			if row.DeviceName == "" {
				row.DeviceName = entry.DeviceName
			}
			rows = append(rows, row)
		}
	}
	return rows, nil
}

// emit aggregates the bounded gauges and emits one twin per device.
func (c *Collector) emit(e telemetry.Emitter, rows []deviceRow) {
	deviceCounts := map[[2]string]int64{}
	tpmCounts := map[string]int64{}
	guardCounts := map[[2]string]int64{}
	storageTotals := map[[2]string]int64{}

	for _, row := range rows {
		osBucket := osBucketFor(row.OperatingSystem)
		hw := row.Hardware
		deviceCounts[[2]string{osBucket, orUnknown(hw.Manufacturer)}]++
		tpmCounts[orUnknown(hw.TPMSpecificationVersion)]++
		guardCounts[[2]string{
			orUnknown(hw.DeviceGuardVBSState),
			orUnknown(hw.DeviceGuardCredentialGuardState),
		}]++
		// totalStorageSpace==0 means "not reported" (a running Linux host reports
		// it), so such a device contributes no storage series at all rather than
		// claiming a zero-byte disk. A zero FREE space under a non-zero total is a
		// real full disk and is summed.
		if hw.TotalStorageSpace > 0 {
			storageTotals[[2]string{osBucket, semconv.StorageStateTotal}] += hw.TotalStorageSpace
			storageTotals[[2]string{osBucket, semconv.StorageStateFree}] += hw.FreeStorageSpace
		}
		e.LogEvent(twin(row))
	}

	devicePoints := make([]telemetry.GaugePoint, 0, len(deviceCounts))
	for k, v := range deviceCounts {
		devicePoints = append(devicePoints, telemetry.GaugePoint{
			Value: float64(v),
			Attrs: telemetry.Attrs{semconv.AttrOperatingSystem: k[0], semconv.AttrManufacturer: k[1]},
		})
	}
	e.GaugeSnapshot(devicesMetricName, "{device}",
		"Intune managed devices reporting hardware inventory, by operating system and hardware manufacturer; per-device detail — storage, TPM chip, firmware, wired IPs, cellular identity — on the intune.device_hardware log twin.",
		devicePoints)

	tpmPoints := make([]telemetry.GaugePoint, 0, len(tpmCounts))
	for k, v := range tpmCounts {
		tpmPoints = append(tpmPoints, telemetry.GaugePoint{
			Value: float64(v),
			Attrs: telemetry.Attrs{semconv.AttrTpmSpecificationVersion: k},
		})
	}
	e.GaugeSnapshot(tpmMetricName, "{device}",
		"Intune managed devices by TPM specification version, emitted verbatim as the comma-joined wire triple (\"2.0, 0, 1.64\"); \"unknown\" for devices reporting no TPM (iOS/macOS/Linux).",
		tpmPoints)

	guardPoints := make([]telemetry.GaugePoint, 0, len(guardCounts))
	for k, v := range guardCounts {
		guardPoints = append(guardPoints, telemetry.GaugePoint{
			Value: float64(v),
			Attrs: telemetry.Attrs{semconv.AttrVbsState: k[0], semconv.AttrCredentialGuardState: k[1]},
		})
	}
	e.GaugeSnapshot(deviceGuardMetricName, "{device}",
		"Intune managed devices by Windows Device Guard virtualization-based-security state and Credential Guard state (wire enums verbatim). Non-Windows devices report Windows-only values here and must not be read as a macOS/iOS/Linux security posture.",
		guardPoints)

	storagePoints := make([]telemetry.GaugePoint, 0, len(storageTotals))
	for k, v := range storageTotals {
		storagePoints = append(storagePoints, telemetry.GaugePoint{
			Value: float64(v),
			Attrs: telemetry.Attrs{semconv.AttrOperatingSystem: k[0], semconv.AttrStorageState: k[1]},
		})
	}
	e.GaugeSnapshot(storageMetricName, "By",
		"Total and free disk bytes summed across Intune managed devices, by operating system. Devices reporting totalStorageSpace=0 (\"not reported\", e.g. Defender-managed Linux hosts) are excluded rather than summed as zero.",
		storagePoints)
}

// twin renders one device's hardware inventory as a log record. The timestamp is
// left zero ("now"): this is a re-emitted state snapshot, not an event stream.
//
// Severity is always INFO. A hardware inventory has no actionable posture
// condition — the candidate thresholds (low free space, degraded battery) would
// be policy this collector has no basis to invent, and the two battery-health
// fields are not even reported.
//
// device_id and device_name are the JOIN KEY back to intune.managed_device, not
// this collector's payload; serial number, model, wifi MAC and isEncrypted are
// deliberately absent because intune.devices already carries them.
func twin(row deviceRow) telemetry.Event {
	hw := row.Hardware
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrDeviceId, row.ID)
	telemetry.SetStr(attrs, semconv.AttrDeviceName, row.DeviceName)
	// The RAW operatingSystem string, matching intune.devices' twin; the gauges
	// above carry the bucketed form under the same key, also matching it.
	telemetry.SetStr(attrs, semconv.AttrOperatingSystem, row.OperatingSystem)
	telemetry.SetStr(attrs, semconv.AttrManufacturer, hw.Manufacturer)

	// Numbers are stamped as STRINGS, the convention every Graph-polled collector
	// in this repo follows (intune/certificates, m365/teams, mdca/discoveryparse):
	// log attributes are Loki structured metadata, which is string-typed, so a
	// native int would round-trip through the OTLP log SDK as an unrenderable
	// value.
	if hw.TotalStorageSpace > 0 {
		attrs[semconv.AttrTotalStorageBytes] = strconv.FormatInt(hw.TotalStorageSpace, 10)
		attrs[semconv.AttrFreeStorageBytes] = strconv.FormatInt(hw.FreeStorageSpace, 10)
	}

	telemetry.SetStr(attrs, semconv.AttrTpmSpecificationVersion, hw.TPMSpecificationVersion)
	telemetry.SetStr(attrs, semconv.AttrTpmManufacturer, hw.TPMManufacturer)
	telemetry.SetStr(attrs, semconv.AttrTpmVersion, hw.TPMVersion)

	telemetry.SetStr(attrs, semconv.AttrSystemManagementBiosVersion, hw.SystemManagementBIOSVersion)
	telemetry.SetStr(attrs, semconv.AttrOperatingSystemEdition, hw.OperatingSystemEdition)
	telemetry.SetStr(attrs, semconv.AttrOperatingSystemLanguage, hw.OperatingSystemLanguage)
	attrs[semconv.AttrOperatingSystemProductType] = strconv.FormatInt(hw.OperatingSystemProductType, 10)
	telemetry.SetStr(attrs, semconv.AttrProductName, hw.ProductName)
	telemetry.SetStr(attrs, semconv.AttrDeviceLicensingStatus, scalarString(hw.DeviceLicensingStatus))

	telemetry.SetStr(attrs, semconv.AttrDeviceGuardHardwareRequirementState, hw.DeviceGuardHardwareRequirementState)
	telemetry.SetStr(attrs, semconv.AttrVbsState, hw.DeviceGuardVBSState)
	telemetry.SetStr(attrs, semconv.AttrCredentialGuardState, hw.DeviceGuardCredentialGuardState)

	telemetry.SetBool(attrs, semconv.AttrIsSupervised, hw.IsSupervised)
	telemetry.SetBool(attrs, semconv.AttrIsSharedDevice, hw.IsSharedDevice)

	if hw.BatteryLevelPercentage != nil {
		attrs[semconv.AttrBatteryLevelPercentage] = strconv.FormatFloat(*hw.BatteryLevelPercentage, 'f', -1, 64)
	}
	// 0 on these two is "not reported", not a reading — see the package doc.
	if hw.BatteryHealthPercentage != 0 {
		attrs[semconv.AttrBatteryHealthPercentage] = strconv.FormatInt(hw.BatteryHealthPercentage, 10)
	}
	if hw.BatteryChargeCycles != 0 {
		attrs[semconv.AttrBatteryChargeCycles] = strconv.FormatInt(hw.BatteryChargeCycles, 10)
	}

	telemetry.SetStrs(attrs, semconv.AttrWiredIpv4Addresses, hw.WiredIPv4Addresses)

	telemetry.SetStr(attrs, semconv.AttrImei, hw.IMEI)
	telemetry.SetStr(attrs, semconv.AttrEsimIdentifier, hw.ESIMIdentifier)
	telemetry.SetStr(attrs, semconv.AttrPhoneNumber, hw.PhoneNumber)
	telemetry.SetStr(attrs, semconv.AttrSubscriberCarrier, hw.SubscriberCarrier)
	telemetry.SetStr(attrs, semconv.AttrCellularTechnology, hw.CellularTechnology)

	return telemetry.Event{
		Name: eventName,
		Body: fmt.Sprintf("device hardware %s: operating_system=%s manufacturer=%s tpm_specification_version=%s",
			deviceLabel(row), row.OperatingSystem, orUnknown(hw.Manufacturer), orUnknown(hw.TPMSpecificationVersion)),
		Severity: telemetry.SeverityInfo,
		Attrs:    attrs,
	}
}

// scalarString renders a JSON scalar that Graph has been observed to send as
// either a string or a number. deviceLicensingStatus is live-verified as a string
// on every m7kni row — including the numeric-looking "25", Graph stringifying an
// enum member it has no name for — but that is n=1, and a strict string decode
// would fail the WHOLE row on a tenant that sends a bare number. Anything that is
// neither yields "" (attribute omitted) rather than failing the row.
func scalarString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var n json.Number
	if err := json.Unmarshal(raw, &n); err == nil {
		return n.String()
	}
	return ""
}

// osPrefixes buckets the free-text managedDevice.operatingSystem property (the
// Graph schema declares no enum for it) into a small fixed set. The prefixes and
// their output values MIRROR intune/manageddevices' osBucketFor deliberately: the
// two collectors emit the same operating_system label key, so a value space that
// disagreed ("Windows" here, "windows" there) would break every cross-collector
// query. A value matching nothing falls into "other", keeping the dimension
// bounded regardless of what a client reports.
var osPrefixes = []struct {
	attr   string
	prefix string
}{
	{"windows", "Windows"},
	{"ipados", "iPadOS"},
	{"ios", "iOS"},
	{"macos", "macOS"},
	{"android", "Android"},
	{"linux", "Linux"},
}

func osBucketFor(raw string) string {
	for _, p := range osPrefixes {
		if len(raw) >= len(p.prefix) && strings.EqualFold(raw[:len(p.prefix)], p.prefix) {
			return p.attr
		}
	}
	return "other"
}

// deviceLabel picks the most human identifier for the log body.
func deviceLabel(row deviceRow) string {
	if row.DeviceName != "" {
		return row.DeviceName
	}
	if row.ID != "" {
		return row.ID
	}
	return unknownValue
}

// orUnknown keeps a bounded gauge dimension from ever carrying an empty label.
func orUnknown(v string) string {
	if v == "" {
		return unknownValue
	}
	return v
}

// isForbidden reports whether err is a Graph 403 — a graceful skip (missing scope
// or Intune absent on this tenant) rather than a collection failure.
func isForbidden(err error) bool {
	if err == nil {
		return false
	}
	if strings.Contains(err.Error(), "status 403") {
		return true
	}
	if code, _, ok := graphclient.UnwrapODataError(err); ok {
		return code == "Authorization_RequestDenied"
	}
	return false
}

var (
	_ collector.SnapshotCollector  = (*Collector)(nil)
	_ collectors.Experimental      = (*Collector)(nil)
	_ preflight.PermissionRequirer = (*Collector)(nil)
)

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Logger)
	})
}
