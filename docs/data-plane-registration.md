# Non-Graph data-plane registration — when a Graph scope is only half the permission

A few Microsoft Graph endpoints are a front end over a data plane that keeps **its own
principal registry**. For those, granting the Graph application permission puts the scope
in the poller's token and changes nothing: the service behind the endpoint has never heard
of your service principal and refuses it. The other half is a **registration in Security &
Compliance PowerShell** — not a Graph scope, not consentable in the Entra admin center, and
not something graph2otel can do for you.

This page is the operator procedure for that second half, and the diagnostic that tells you
whether you need it. Read it **before** granting `eDiscovery.Read.All` — the grant alone
will not produce data, and the failure gives you nothing to work with.

**Evidence tags**, as in [graph-api-gotchas.md](graph-api-gotchas.md): `[live YYYY-MM-DD,
#issue]` was measured on the wire against a real tenant under the poller's own identity;
`[docs-only]` is believed from Microsoft's documentation and cheap to re-open; `[n=1]` is a
single observation; `[unverified]` is not established either way. Microsoft's documentation
has been wrong on essentially every load-bearing detail on this path — **wire over docs**.

## The diagnostic: the status code is the whole tell

Both outcomes below were observed **in the same tenant in the same session**, on two Purview
endpoints. They look alike and are different systems failing for different reasons.

| symptom | meaning | fix |
| --- | --- | --- |
| **403** `InsufficientGraphPermissions` | Graph is refusing you. The scope is genuinely missing or not admin-consented. | Grant + consent the endpoint's **documented** Application permission `[live 2026-07-16, #126]` |
| **401**, scope already in the token | Graph let it through. A **non-Graph data plane** behind the endpoint does not know your principal. | This page. No amount of Graph scope will move it `[live 2026-07-16, #102]` |

Corroborating detail that rules out the alternatives `[live 2026-07-16, #102]`:

- `GET /v1.0/security/cases` → **200**, but `GET /v1.0/security/cases/ediscoveryCases` →
  **401** `UnknownError` (empty message), v1.0 and beta alike. The parent is Graph-served;
  the child hits the Purview data plane. So this is not routing, and not the token being
  rejected wholesale.
- `GET /v1.0/compliance/ediscovery/cases` → **401** `Unauthorized` with
  `ServiceFabricGraphAuthenticationMiddleware.ValidateToken` in the message — the compliance
  data plane rejecting the principal, exactly as the middleware name says.
- **401 is not 403.** It is not "you lack a scope", it is "I cannot identify you", from a
  service where the principal does not exist.

Do not generalize either result. A 403 means missing consent far more often than product
limitation (#109 called a missing scope a permanent gap and was wrong). But a grant can also
be insufficient (#102). **Verify, never infer, in both directions.**

`graph2otel check` cannot see this failure mode: it reports whether a permission is granted
and consented, which for a token holding `eDiscovery.Read.All` is a clean pass while the
endpoint 401s. See [permissions.md](permissions.md) for the caveats it documents about
itself.

## Who needs it

| surface | Graph half | data-plane half | status |
| --- | --- | --- | --- |
| Purview **eDiscovery** (`security/cases/ediscoveryCases`) | `eDiscovery.Read.All` | **required** — this page | 401 → 200 once run `[live 2026-07-17, #102/#148]` |
| Purview **sensitivity** labels (`security/dataSecurityAndGovernance/sensitivityLabels`) | `SensitivityLabel.Read` | not needed | 200 app-only on the Graph scope alone `[live 2026-07-16, #126]` |
| **O365 Management Activity API** (`m365.activity`) | — | not needed | A non-Graph data plane that authorizes on Entra app roles (`ActivityFeed.Read`) directly — see [o365-management-api.md](o365-management-api.md) |
| Everything else shipped | Graph scopes only | not needed | No other shipped collector sits behind an S&C-registered data plane (audit, #149) |

**Audit result:** eDiscovery is the only surface on graph2otel's map that needs this. Every
other Purview and M365 collector either takes a plain Graph application permission, or takes
none because it reads a different data plane with its own Entra app roles. Recorded so the
absence of findings is on the record rather than assumed.

## What this does not fix

Registering the principal makes a data plane recognize you. It does **not** create an API
where none exists. These are named so you do not run the procedure hoping:

- **Purview retention labels** — `GET /security/labels/retentionLabels` → 500
  `DataInsightsRequestError` + "Forbidden" on v1.0 and beta with `RecordsManagement.Read.All`
  granted and in the token `[live 2026-07-16, #109/#126]`. Microsoft's permission table says
  **Application: Not supported** `[docs-only]`. This is a product gap, not a registration gap.
  Retention label *definitions* being Graph-exposed does not change the app-only verdict.
- **Retention policy location bindings** — S&C PowerShell only
  (`Get-RetentionCompliancePolicy`), no Graph list equivalent `[live, #99]`.

> **Correction (`live-measured 2026-07-23, #237`):** an earlier version of this list said
> "DLP policy enumeration — the Purview APIs evaluate content *against* policy; they never
> enumerate policy." That generalization was true of the #99 Purview Ecosystem roles and is
> **false of Graph**: `GET /beta/security/dataSecurityAndGovernance/policyFiles` returns the
> full DLP policy set app-only, on scopes the poller already holds — no data-plane registration
> needed. #246 builds it. Only retention policy *bindings* remain a genuine gap.

The distinction that matters: this procedure only helps where **a Graph endpoint exists and
the data plane behind it refuses you**. Retention bindings *are*
reachable from S&C PowerShell — but graph2otel speaks Graph at runtime, never PowerShell, so
a reachable-only-from-PowerShell surface is out of reach regardless of what you register.

## The procedure

Run once per app registration, per tenant. It mutates the tenant. Every value below is a
placeholder except the device-code client id in step 1.

### 0. Resolve the object id — this is the trap

The role-group cmdlets take the **enterprise-application object id**, not the `appId`. They
are different GUIDs for the same app, and using the `appId` is the documented common mistake
`[docs-only]`. On the reference tenant the two values are unrelated strings and neither is
derivable from the other `[live 2026-07-17, #102/#148]`.

Resolve it from Graph and read `.id`:

```
GET https://graph.microsoft.com/v1.0/servicePrincipals(appId='<appId>')
```

The `id` this returns is the value to paste into `-ObjectId`, `-Member`, and `-User` below.
It was confirmed correct against the live directory before the cmdlets ran
`[live 2026-07-17, #102/#148]`.

### 1. Connect — app-only does not work; use a delegated device-code token

**Do not plan around app-only `Connect-IPPSSession`.** On the reference tenant it fails, and
a Windows host does not fix it `[live 2026-07-17, #102/#148]`:

| environment | result |
| --- | --- |
| Windows Server, PowerShell 5.1, EXO 3.10.0, certificate in store (`-CertificateThumbprint`) | `Object reference not set to an instance of an object.` |
| macOS, pwsh 7.6.3, EXO 3.10.0, pfx (`-Certificate`) | identical NullRef |

Same module version, same identity, same org, two operating systems, byte-identical failure.
`-Verbose` places it **after** authentication — `Successfully got a token from AAD`, then a
NullRef in `Microsoft.Exchange.Management.ExoPowershellSnapin.NewEXOModule.ProcessRecord()`.
Ruled out with evidence: not the platform (Windows reproduces it); not the certificate or the
identity (`Connect-ExchangeOnline` with the *same* pfx from the *same* host connects and
returns live data); not a missing role (the identity held Compliance Administrator, Security
Administrator, Exchange Administrator and `Exchange.ManageAsApp`, live-read); not replication
lag (three days). **Why app-only fails is open** `[unverified]` — the obvious explanation, "the
principal is unknown to compliance RBAC", is refuted: that principal *was* already registered
and it still NullRefs `[live 2026-07-17, #102]`.

A **delegated device-code token connects first try** from the same host that fails app-only
`[live 2026-07-17, #102/#148]`. There is also a bootstrap argument for it:
`New-ServicePrincipal` is itself an S&C cmdlet, so registering a principal for app-only access
appears to require an already-working session, which app-only cannot give you. That is a
deduction from the cmdlet's location, not a measurement `[unverified]`.

The device-code client id matters `[live 2026-07-17, #149]`:

| client id | name | result |
| --- | --- | --- |
| `a0c73c16-a7e3-4564-9a95-2bdf47383716` | Microsoft Exchange Online Remote PowerShell | `AADSTS7000112: Application is disabled` |
| `fb78d390-0c51-40cd-8e17-fdbfab77341b` | Microsoft Exchange REST API Based Powershell | **works** |

Scope: `https://ps.compliance.protection.outlook.com/.default`.

```powershell
Install-Module ExchangeOnlineManagement    # 3.10.0 is the measured version
Import-Module ExchangeOnlineManagement

# $token: delegated device-code token for client fb78d390-… , scope above.
Connect-IPPSSession -AccessToken $token -Organization "<tenant>.onmicrosoft.com"
```

The signing-in user must be able to run `New-ServicePrincipal` and `Add-RoleGroupMember`; on
the reference tenant this was a Global Administrator `[live 2026-07-17, #102/#148]`. **The
minimum role that suffices was not established** `[unverified]` — if you establish it, that is
worth recording. The `-AccessToken` / `-Organization` parameter spelling above is also
`[unverified]`: the issues record that the token was acquired and the session connected, not
the cmdlet's exact parameter form.

### 2. Register the principal and grant the role

`Get-ServicePrincipal` first — it lists what the compliance data plane already knows, and an
app registered by some earlier process will already be there `[live 2026-07-17, #102]`.

```powershell
Get-ServicePrincipal

New-ServicePrincipal -AppId "<appId>" `
                     -ObjectId "<enterprise app object id, from step 0>" `
                     -DisplayName "graph2otel-poller"

Add-RoleGroupMember -Identity "eDiscoveryManager" -Member "<object id>"
Get-RoleGroupMember -Identity "eDiscoveryManager"

Add-eDiscoveryCaseAdmin -User "<object id>"
Get-eDiscoveryCaseAdmin
```

**On least privilege.** These three ran as one batch, so **which subset is minimally
sufficient is unverified** — the 401 → 200 transition is attributable to the batch, not to any
one cmdlet. `eDiscoveryManager` is not a read-only role group; Microsoft documents it as able
to create and manage cases `[docs-only]`, which is more than a telemetry poller needs. A
`Reviewer` role group was named as the lower-privileged alternative when the fix was scoped
`[#102]` and **was not tested** `[unverified]`. If you want strict read-only, try `Reviewer`
first, and record what happens — a narrower working configuration is a finding this page
should carry.

### 3. Verify — re-request the endpoint as the poller

Mint a **fresh** token (app-only tokens embed `roles` at issue time) with the poller's own
credentials, and request the endpoint that was failing:

```
GET https://graph.microsoft.com/v1.0/security/cases/ediscoveryCases
```

Expect **200** where you had 401. Measured on the reference tenant, v1.0 and beta both moved
401 → 200, one live case returned `[live 2026-07-17, #102/#148]`.

**Do not wait 24 hours.** The ≤24h compliance-RBAC replication lag that Microsoft's guidance
implies did not apply: the probe returned 200 on the **first attempt, immediately after the
cmdlets**, with no wait `[live 2026-07-17, #102/#148]`. If yours still 401s, *then* replication
is a candidate — as a fallback explanation, not as an instruction.

Probe as the poller identity itself, never with another app. A different app's access answers
a different question — that is how #109 reached a wrong verdict, and the verdict then
suppressed re-investigation until #126 re-probed correctly.

## Runtime: graph2otel never speaks PowerShell

This is a one-time setup action, not a dependency. graph2otel reads eDiscovery over Graph as
the poller, with `eDiscovery.Read.All`, like every other collector `[live 2026-07-17, #102]`.
Nothing in the binary imports, shells out to, or requires the ExchangeOnlineManagement module.
If you rotate to a **new app registration**, the new principal needs its own registration — the
compliance data plane keys on the principal, not the tenant. Whether a registration ever
expires or needs re-running is `[unverified]`; the reference tenant's is one day old.

`eDiscovery.Read.All` stays granted after this runs: it is read-only, and it is half of a
working configuration rather than a permission the poller cannot use.
