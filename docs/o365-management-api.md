# O365 Management Activity API — how `m365.activity` actually works

The Office 365 Management Activity API (`manage.office.com`) feeds `m365.activity`
(default-on) via `internal/o365activityclient` + `internal/o365pipeline`. It is a
**stable v1.0** transport (2,000 req/min per tenant) with a subscription → content-blob
model built for continuous ingest — chosen over the Graph audit query API, which is
beta-only on this tenant and 429s on rapid job creation (#100, #109). App roles:
`ActivityFeed.Read` on the O365 Management APIs service principal
(`c5393580-f805-4401-95e8-94b7a6ef2fc2`); add `ActivityFeed.ReadDlp` only when the
operator explicitly selects `DLP.All`.

Everything below is live-measured (2026-07-16, #100) unless noted. The doc-vs-wire
scorecard ran **6-0 against Microsoft's documentation** — treat the docs as hypotheses.

## Wire format traps

- **`CreationTime` is NOT RFC3339.** It arrives zone-less (`"2015-06-29T20:03:19"`) —
  `time.Parse(time.RFC3339, …)` fails and would silently drop **every** record. The
  mapper tries `RFC3339Nano` first (so a future `Z` is honored), then falls back to
  `"2006-01-02T15:04:05.999999999"` parsed as UTC — with **no `time.Now()` fallback**
  (a stamped-on-arrival record silently claims to have happened now; worse than a drop).
- **Docs declare camelCase enums; the wire returns PascalCase.** Requests take camelCase
  (`exchangeAdmin`), responses return PascalCase (`ExchangeAdmin`) — the API passes the
  classic O365 names straight through (#98 corroborates from the query-API side).
- **The published `AuditLogRecordType` table misses ~27% of this tenant's live types.**
  Six observed members are absent from the docs at any int, plus RecordType 117. So the
  unknown-int path fires on day one: `m365.activity` emits `record_type_id`
  **unconditionally** (the only lossless form) and `record_type` only when the int
  resolves. **Never guess a name** — a guessed name is a silent convergence break; an
  absent one is visibly unknown. Docs rows containing a space ("Viva Engage") are
  deliberately omitted — that is post-rename display text, the wire keeps the old name.

## Subscription lifecycle traps

- **AF20024 is undocumented and fires on every re-start of an enabled subscription.**
  `POST /subscriptions/start` on an already-enabled content type → 400 `AF20024` ("The
  subscription is already enabled. No property change."). It is a **success condition**
  (the desired state holds): `IsAlreadyEnabled` treats it as one (`55e3999`). Without
  that, the collector works exactly once per tenant, then fails every tick forever.
  The test fake reproduces the 400 — a fake returning 200 unconditionally is kinder than
  the wire and proves nothing.
- **`POST /subscriptions/start` is a WRITE operation** — the second break in graph2otel's
  read-only property (after the Intune reports-export job).
- **No server-side filtering exists.** Subscribe only to content types actually mapped —
  never `Audit.General` by default (it is the catch-all, including Teams; opt-in only).

## Teams audit filtering

To keep Microsoft Teams (25) and Microsoft Teams Admin (57) records from
`Audit.General`, set the following in that tenant's YAML. Use `[25]` if you do
not want the admin records. Neither list is a catch-all for Teams-related audit
records.

```yaml
o365_activity:
  content_types: [Audit.General]
  record_type_allow_list: [25, 57]
```

The API still lists and downloads the full `Audit.General` blobs. The allow-list
saves downstream log ingest, not API traffic. It selects by numeric `RecordType`,
not workload or operation, and applies to all configured content types. Endpoint
DLP (63) and other non-matching records are counted as `filtered` before mapping.
Omitting the list or setting it to `[]` leaves record selection unchanged. The
checkpoint still advances through the blobs, so widening or removing the list
does not replay records that were filtered before.

Live-measured 2026-11-25: a read-only probe of the existing `Audit.General`
subscription saw `TeamCreated`, `MemberAdded`, `TeamSettingChanged`,
`ChannelAdded`, `TabAdded` and `TeamsSessionStarted` under type 25, and
`TeamsAdminAction` and `WriteUserObjPreference` under type 57. Meeting and
call records followed on 2026-11-25 and 2026-11-26: `MeetingDetail`,
`MeetingParticipantDetail` and `CallParticipantDetail`, plus `AppDeleted`
and the chat and message operations.

### Teams fields on `m365.audit`

Type 25 records with workload `MicrosoftTeams` carry these attributes beside
the generic ones, each only when the record has the source field. Type 57
records keep the generic attributes only.

| Attribute | Source field | Seen on |
| --- | --- | --- |
| `team_guid`, `team_name`, `channel_guid`, `channel_name` | `TeamGuid`, `TeamName`, `ChannelGuid`, `ChannelName` | team, channel, tab, message and channel-meeting records |
| `teams_members_json`, `teams_members_count`, `teams_members_truncated` | `Members` | `MemberAdded` |
| `teams_meeting_detail_id` | `MeetingDetailId` | `MeetingParticipantDetail` |
| `call_id` | `CallId` | `CallParticipantDetail` |
| `teams_join_time`, `teams_leave_time`, `teams_joined_from_lobby` | `JoinTime`, `LeaveTime`, `IsJoinedFromLobby` | participant records |
| `teams_meeting_start_time`, `teams_meeting_end_time`, `teams_meeting_url` | `StartTime`, `EndTime`, `MeetingURL` | `MeetingDetail` |
| `teams_communication_type`, `teams_communication_sub_type`, `teams_modalities`, `teams_provider_types` | the fields of the same names | `CommunicationType` on most records, the rest on `MeetingDetail` |
| `teams_organizer_object_id`, `teams_organizer_organization_id` | `Organizer.UserObjectId`, `Organizer.OrganizationId` | meeting records |
| `teams_attendees_json`, `teams_attendees_count`, `teams_attendees_truncated` | `Attendees`, including `InviterInfo` | participant records |
| `user_agent`, `teams_users_invited_during_meeting`, `teams_rtmp_in_enabled` | `ExtraProperties` keys `UserAgent`, `UsersInvitedDuringMeeting`, `RTMPInEnabled` | meeting and call records |
| `teams_device_id`, `teams_device_information` | `DeviceId`, `DeviceInformation` | session, sign-out and participant records |
| `teams_addon_id`, `teams_addon_type_id`, `teams_addon_name`, `teams_tab_type` | `AddOnGuid`, `AddOnType`, `AddOnName`, `TabType` | `AppDeleted`, `TabAdded` |
| `teams_has_foreign_tenant_users`, `teams_has_guest_users`, `teams_has_other_guest_users`, `teams_has_unauthenticated_users`, `teams_participating_tenant_ids` | `ParticipantInfo` | team, channel, chat, message and call records |

The member and attendee lists are JSON arrays of the observed keys only, capped
at 50 rows and 8 KiB. The `_count` attribute is the full wire count, so a
capped list still says how many there were. The join, leave, start and end
times arrive without a zone, like `CreationTime`, and are emitted as RFC 3339
UTC. Times inside the JSON lists, such as an inviter's `invite_time`, stay as
served.

Wire facts `[live-measured 2026-11-26, #665]`, from 12 redacted records in
`internal/collectors/m365/activity/testdata/teams_audit_live.json`:

- `MeetingParticipantDetail.MeetingDetailId` equals the `Id` of the
  `MeetingDetail` record for the same meeting in 8 of 8 sampled pairs. Join
  `teams_meeting_detail_id` to the meeting record's `id`.
- `CallParticipantDetail.CallId` matched `call_id` on a `teams.call` log for
  both calls checked, so it uses the same attribute name.
- `MeetingURL` is served without a scheme. With `https://` in front it
  matched a `teams.call` `join_web_url` exactly, in the one case checked. It
  is emitted as served. It was present on channel meetings and absent on the
  ad hoc and escalated calls.
- A meeting's `CreationTime` was up to about 8.5 hours after its `StartTime`.
  Use `teams_meeting_start_time` for when the meeting happened.
- On a missed call, `JoinTime` equals `LeaveTime`.
- A PSTN attendee's `DisplayName` is its phone number. A bot attendee's
  `DisplayName` was the bot's app id.
- `AddOnGuid` is a bare GUID on `AppDeleted` and `tab::<guid>` on
  `TabAdded`. It has not been matched against Graph's Teams app catalogue, so
  it is named for the field. `AddOnType` is emitted as a number because no
  sample shows its names.
- A Teams session's `object_id` was a client descriptor shaped like
  `<platform> (<number>/<version>)`, not a team, channel or meeting id.
- `ConferenceUri` was empty on every meeting record, and
  `ParticipatingDomains` and `ParticipatingSIPDomains` were empty lists on
  every record, so none of them is read.

If you need to reduce what you fetch, the experimental Graph collector
`m365.unified_audit` uses a fixed server-side `recordTypeFilters` list that
includes `microsoftTeams`, `microsoftTeamsAdmin` and `teamsQuarantineMetadata`,
among other record types, and excludes Endpoint DLP. This is not a Teams-only
query or a configurable workload filter. Disable `m365.activity` before
enabling the alternative. Graph uses a slower, beta async query and can
throttle query creation.

## Windowing and retention

- **`/subscriptions/content` caps the list range at 24 HOURS** — `startTime`/`endTime`
  must both be set or both omitted and be ≤24h apart; a wider request → 400 `AF20055`.
  Worse: a >24h range that *does* return 200 may be **silently partial** (per the API
  reference). Always chunk into ≤24h sub-windows (`o365activityclient.MaxWindow`).
- **There is NO 12-hour delay for first content** (docs claim one). Content listed ~2
  minutes after subscribe, with the oldest `contentCreated` ~22h **before** the
  subscription existed — Microsoft backfills on subscribe. Never build a "wait before
  first poll" behavior; never tell a reader an empty first poll is expected.
- **The "7-day content expiry" is unverified and probably a docs conflation.** Live:
  `contentExpiration` ~20 days after `contentCreated`. AF20051 is a *retrieval* bound;
  AF20030/AF20055 are a *startTime lookback* bound (`MaxLookback` — measured). **Always
  read `contentExpiration` off the wire; never derive expiry from a constant.**

## Cursor and dedupe rules (mutation-proven, `o365pipeline`)

- **A cursor's clock and its eviction clock must be the SAME clock, and here it is the
  ARRIVAL clock.** Seen-set ids evict on their blob's `contentCreated` (arrival), never
  the record's own `CreationTime` (event) — one content blob can contain events that
  occurred before an earlier blob's, so evicting on event time drops ids whose blobs are
  still re-listable inside the overlap window → silent duplicates. The rule is NOT
  "prefer arrival time" — it is that the two clocks must match; envelope `time` *loses*
  on the blob sign-in categories by the same rule (see blob-ingest.md).
- **Guard the empty dedupe id.** A bare `"record:"` key for an id-less record matches
  every later id-less record — record two onward vanish silently forever. Companion
  rule: **undedupeable is degraded; misdated is wrong — only wrong justifies a drop.**
  An id-less record is still emitted; a record with no parseable event time is dropped.

## Operational behavior

- **The defaults (`Audit.Exchange` + `Audit.SharePoint`) carry ZERO content on a small
  tenant, and the collector looks 100% healthy doing it** — `runs=1 failures=0` with an
  empty checkpoint is the steady state, not a fault. `advance()` moves the watermark only
  to blobs actually consumed. Anyone validating against defaults will conclude it is
  broken, or worse, that it works.
- **`m365.unified_audit` must be disabled wherever `m365.activity` runs** — both emit
  `m365.audit` with the same ids; both on = every record twice.

## Current completion state

All four #100 residuals are discharged. The classic schema emits its UPN-shaped identity as
`user_id` rather than asserting that every value is a UPN; the `WindowCollector` adapter lives in
`internal/o365pipeline`; `SECURITY.md` records the subscription-start write; and `DLP.All` was
live-measured with three records. A dedicated `DLP.All` mapper is deliberately absent: those
records are normally empty on m7kni and `DetectedValues` contains the matched secret in cleartext.
Any future mapper must be built from a live sample, emit classification metadata only, and exclude
`DetectedValues`.
