# Teams admin API (`teams_admin`)

The `teams_admin` transport reads Teams voice configuration that has no Microsoft
Graph surface: auto attendant (AA) and call queue (CQ) configuration, Direct Routing
gateway (SBC) configuration, the tenant network topology (regions, sites, subnets)
and SIP device and IP phone policy. It calls the REST API behind the MicrosoftTeams
PowerShell `Get-Cs*` cmdlets directly from Go (`internal/teamsadminclient`, #712).
It is opt-in per tenant: see `tenants[].teams.admin_api.enabled` in
[Configuration](configuration.md).

Every fact below was measured on the wire on 2026-11-25 as the `graph2otel-poller`
identity against a small Teams calling lab, and is tagged `live-measured 2026-11-25`.
The API is undocumented: treat anything not tagged, or listed under
"Unmeasured", as an assumption.

## Paths

Every cmdlet in scope is one HTTPS GET on `https://api.interfaces.records.teams.microsoft.com`.
The MicrosoftTeams 8.1.0 module's debug trace names the paths (live-measured 2026-11-25):

| Cmdlet | Path |
| --- | --- |
| `Get-CsAutoAttendant` | `/Teams.VoiceApps/auto-attendants` |
| `Get-CsCallQueue` | `/Teams.VoiceApps/callqueues?FilterInvalidObos=False` |
| `Get-CsTenantNetworkRegion`, `-Site`, `-Subnet` | `/Skype.Policy/configurations/TenantNetworkRegion` (`Site`, `Subnet`) |
| `Get-CsOnlinePSTNGateway` | `/Skype.Policy/configurations/OnlinePSTNGateway` |
| `Get-CsTeamsSipDevicesConfiguration` | `/Skype.Policy/configurations/TeamsSipDevicesConfiguration` |
| `Get-CsTeamsIPPhonePolicy` | `/Skype.Policy/configurations/TeamsIPPhonePolicy` |
| `Get-CsOnlineUser` (out of scope) | `/Teams.User/users` |
| `Get-CsPhoneNumberAssignment` (out of scope) | `/Skype.TelephoneNumberMgmt/cmdlet/assignments` |

## Authentication

- A plain OAuth client-credentials token, minted with the poller's existing
  certificate for scope `48ac35b8-9aa8-4d74-927d-1f4a14a0b239/.default` (the "Skype
  and Teams Tenant Admin API" resource), returns the same JSON bodies the module's
  debug trace shows. *(live-measured 2026-11-25)*
- The probe sent only `Authorization` and `Accept` headers, none of the module's own
  headers. Each call took 120 to 390 ms. *(live-measured 2026-11-25)*
- The token carries **no `roles` claim**: no app permission is involved.
  Authorization comes from the Entra directory roles in the token's `wids` claim.
  The poller already held Global Reader, so no grant was made. *(live-measured 2026-11-25)*

## Response shapes

- `Skype.Policy/configurations/*` returns a bare JSON array. Its enumerations are
  strings (`"SignInMode": "UserSignIn"`, `"BypassMode": "None"`). *(live-measured 2026-11-25)*
- `Teams.VoiceApps/*` returns an object: `{"AutoAttendants": [...], "Diagnostics": [...]}`
  or `{"CallQueues": [...], "Diagnostics": [...]}`. A `Diagnostics` entry is
  `{"Level": "Warning", "Message": "..."}` with **no object reference**; the lab's two
  queues produced two identical conference-mode warnings. *(live-measured 2026-11-25)*
- Auto attendant enumerations are strings (`"Action": "TransferCallToTarget"`,
  `"Type": "ApplicationEndpoint"`). *(live-measured 2026-11-25)*
- **Call queue enumerations are integers** on the wire: `RoutingMethod`,
  `OverflowAction`, `TimeoutAction`, `NoAgentAction` and `NoAgentApplyTo`. PowerShell
  shows names. *(live-measured 2026-11-25)* The lab confirms `RoutingMethod` 2 (RoundRobin) and 3
  (LongestIdle) against the configuration its ledger records; the other values rest
  on the module types alone (see "Enum tables").
- One field name is misspelt on the wire: `OutbundTeamsNumberTranslationRules`. *(live-measured 2026-11-25)*
- The object ID field is `Id` for auto attendants and `Identity` for call queues. *(live-measured 2026-11-25)*

## Paging

- On `Teams.VoiceApps`, `First` and `Skip` are honoured. `First=1&Skip=0` and
  `First=1&Skip=1` returned the two queues in the same order as the unpaged list;
  `First=1&Skip=2` and `First=100&Skip=100` returned an empty list. *(live-measured 2026-11-25)*
- Invalid values are **silently ignored**: `First=bogus` and `First=0` both return
  the full list. *(live-measured 2026-11-25)*
- `Skype.Policy/configurations/*` returned everything unpaged and takes no paging
  parameter we know of. *(live-measured 2026-11-25)*
- The default and maximum page sizes are unknown (see "Unmeasured").

The client therefore walks pages until an **empty** page, and treats a page longer
than `First`, an object ID seen on an earlier page, or more than 50 non-empty pages
as errors, because the API would otherwise hide a paging parameter it ignored.

## Stability

Two full reads three minutes apart returned identical objects for all eight
resources, including `ETag` and `DistributionListsLastExpanded`. *(live-measured 2026-11-25)* So a hash over
the exported attributes is stable between polls of an unchanged object.

## Errors

Errors come in two envelopes (live-measured 2026-11-25):

- `{"code","message","action","errorCode"}` served as `text/plain`: an unknown
  configuration name gives HTTP 400 with `errorCode` 40001.
- `{"Error": {"Code","Message"}}`: a bad number-management query gives HTTP 400.

No `Retry-After` or rate-limit header was seen. *(live-measured 2026-11-25)*

## Enum tables

Only the five call-queue integer enums are mapped. Source: MicrosoftTeams 8.1.0,
namespace `Microsoft.Rtc.Management.Hosted.HuntGroup.Models`, read by reflection on
2026-11-25. Only `RoutingMethod` 2 and 3 were confirmed against the lab; every other
row rests on the module types alone.

| Wire field | Values |
| --- | --- |
| `RoutingMethod` | 0 Attendant, 1 Serial, 2 RoundRobin, 3 LongestIdle |
| `OverflowAction` | 0 DisconnectWithBusy, 1 Forward, 2 Voicemail, 3 SharedVoicemail |
| `TimeoutAction` | 0 Disconnect, 1 Forward, 2 Voicemail, 3 SharedVoicemail |
| `NoAgentAction` | 0 Queue, 1 Disconnect, 2 Forward, 3 Voicemail, 4 SharedVoicemail |
| `NoAgentApplyTo` | 0 NewCalls, 1 AllCalls |

An integer outside a table is exported as `unknown` plus the raw integer and reported
through the `wirecheck` watchdog; it is never dropped.

## Unmeasured

These were not measured and must not be asserted:

- The least-privileged Entra directory role. Global Reader works; whether Teams
  Reader or Teams Communications Support Engineer is enough is unknown.
- The response to a token with no sufficient directory role (403, or 200 with empty
  lists).
- Throttling: the status code, any header, and any rate limit.
- Redirect behaviour. The client refuses redirects so a bearer token cannot follow
  one to another host.
- The default and maximum `Teams.VoiceApps` page sizes.
- Whether the `*FileDownloadUri` fields are signed URLs (the lab has no audio files).
  They are not exported.
- Every call-queue enum value other than `RoutingMethod` 2 and 3.
- The shape of a call queue `<family>ActionTarget` other than an object with `Id`
  and `Type`.
- Sovereign clouds. The base URL and scope are the commercial-cloud values.
- `Get-CsOnlineUser` and `Get-CsPhoneNumberAssignment` at scale (out of scope).
