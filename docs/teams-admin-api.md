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

### Directory roles

Each role below was assigned alone to a separate test app registration that held
no other directory role, and every endpoint in "Paths" except the two out-of-scope
ones was read with a fresh token. A role appeared in `wids` within 30 seconds of
assignment; each failing role was re-read for ten minutes before it was recorded as
failing. *(live-measured 2026-11-25)*

| Directory role | `Teams.VoiceApps` | `Skype.Policy/configurations` |
| --- | --- | --- |
| None | 403 `Access Denied.` | 403 `Access Denied.` |
| Teams Communications Support Specialist | 403 `Access Denied.` | 403 `errorCode` 40301 |
| Teams Communications Support Engineer | 403 `Access Denied.` | 403 `errorCode` 40301 |
| **Teams Reader** | **200** | **200** |
| Global Reader | 200 | 200 |

**Teams Reader is the least-privileged role that works**: every resource returned
the same counts as the poller's Global Reader read, on the first read after the
role reached the token. Removing the role restored the 403 at once. A token with no
sufficient role gets a **403, never a 200 with empty lists**, so a missing role
cannot pass for an empty tenant.

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

A missing directory role gives HTTP 403 with `"code": "Forbidden"` and one of two
messages: `Access Denied.` with no `errorCode` when no accepted role is present,
or `You are not authorized to perform this action` with `errorCode` 40301 on
`Skype.Policy/configurations` when the token holds a Teams Communications support
role. Both name no role. *(live-measured 2026-11-25)*

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
- Paging of `Teams.User/users` beyond one page (see "Users").

## Users (out of scope)

`Get-CsOnlineUser` calls `/Teams.User/users?$top=<n>&$skipuserpolicies=False&defaultpropertyset=Extended`
(#725). It was measured to decide whether a per-user policy collector would add
anything to `teams.user_configuration`; it does not, so no collector reads it.
*(live-measured 2026-11-25)*

- **The response depends on a header.** Without `X-MS-CmdletName: Get-CsOnlineUser`
  the same URL returns 14 directory fields per user and no policy data at all. With
  it, 47 fields including `effectivePolicyAssignments`, `teamsCallingPolicy`,
  `onlineVoiceRoutingPolicy`, `teamsUpgradeEffectiveMode` and `lineUri`.
- `effectivePolicyAssignments` is a list of `{policyType, policyAssignment:
  {policyId, displayName, assignmentType, authority}}`. For all 27 lab users its
  policy types match what the cmdlet returns and what Graph's
  `/admin/teams/userConfigurations` returns, user for user.
- `$top` is honoured and `First` is ignored. `$skip` gives HTTP 400 "Skip query
  parameter is not supported". `$top=0` and an absent `$top` return everyone. A
  bad `$skiptoken` gives 400. No continuation token appeared in the body or the
  headers on a `$top=5` page of 27 users, so how the service pages a large tenant
  is unknown.
- 27 users came to 112 KB (919 to 7,888 bytes per user) in one call of about
  570 ms.
