# Permission setup

`graph2otel` authenticates against each configured tenant as an app-only (client-credentials)
Microsoft Entra ID app registration — there is no signed-in user. This page walks through
registering that app, granting it the right Graph API application permissions, and the three
gotchas that catch most first-run setups. For the per-collector scope list, see
[`collectors.md`](./collectors.md); for the config schema those collectors are toggled from, see
[`configuration.md`](./configuration.md).

## 1. Register the app

1. In the Entra admin center (or `az ad app create`), create an app registration in each tenant
   you want to poll — or a single multi-tenant app registration reused across tenants, if your
   tenants are all under your own management.
2. Under **Certificates & secrets**, create a client secret, or (preferred for production) upload
   a certificate. `graph2otel` reads whichever you configure via
   `azidentity.DefaultAzureCredential`:

   ```sh
   export AZURE_TENANT_ID="<tenant guid>"
   export AZURE_CLIENT_ID="<app registration client id>"
   export AZURE_CLIENT_SECRET="..."          # or, for certificate auth:
   # export AZURE_CLIENT_CERTIFICATE_PATH="/path/to/cert.pem"
   ```

   These are environment variables, never YAML — see [`configuration.md`](./configuration.md) for
   why. Ambient workload/managed identity also works if the host provides it.
3. Under **API permissions**, add the **application permissions** (not delegated) your enabled
   collectors need. Start from [`collectors.md`](./collectors.md)'s per-collector scope column, or
   run `graph2otel check` (below) once the app registration exists, which prints a representative,
   domain-grouped scope catalog.

## 2. Grant admin consent (gotcha #1)

Adding an application permission to the app registration is **not** enough on its own — application
permissions require a **tenant administrator to grant admin consent** before the permission is
actually usable. This is the most common first-run failure: the permission shows as added in the
Entra admin center, but every Graph call using it returns **HTTP 403** until consent is granted.

In the Entra admin center: **API permissions** → **Grant admin consent for `<tenant>`**. This must
be done by a Global Administrator or Privileged Role Administrator (or whoever your tenant's consent
policy authorizes) — a plain app-registration owner cannot self-consent to application permissions.

## 3. Directory-role gating (gotcha #2 — partially confirmed)

Most Graph application permissions are sufficient on their own once consented. A smaller set of
surfaces — notably **Identity Protection** (`entra.risk`, `entra.risk_detections`) — have been
observed in Microsoft's own documentation to additionally expect the calling service principal to
hold a directory role, not just the API permission grant. A service principal can have the right
permission scope, fully consented, and still get a 403 at runtime if this additional gate applies
and the role isn't assigned.

**What's confirmed here:** graph2otel's collectors request only the documented API permission scope
for each endpoint (see [`collectors.md`](./collectors.md)); none of them require a directory role
assignment as a hard prerequisite that's been verified failing without one in this project's own
testing. **What's still open:** which specific endpoints enforce a directory-role check in practice,
beyond what Microsoft's docs state, hasn't been exhaustively reproduced against a live tenant by this
project. If a collector 403s despite a correctly consented permission, check whether the calling
service principal also needs a directory role (e.g., Security Reader) before filing it as a
graph2otel bug.

`graph2otel check` (see below) can only tell you whether a permission is granted and consented — it
has no way to enumerate a service principal's directory-role assignments, so it cannot detect this
failure mode. Its own help text calls this limitation out explicitly.

## 4. The export-job ReadWrite caveat (gotcha #3)

Six opt-in Intune collectors — `intune.app_install_status`, `intune.cert_inventory`,
`intune.defender_agents`, `intune.config_assignment_status`, `intune.noncompliant_settings`, and
`intune.device_attestation` — read their data via the **Intune Reports Export API**
(`POST /deviceManagement/reports/exportJobs`, then poll and download the result). That API requires
**`DeviceManagementManagedDevices.ReadWrite.All`**, a write-level scope, purely to **create** the
export job. This is documented Microsoft Graph behavior, not a graph2otel design choice.

If you're setting these collectors up and notice a read-only telemetry exporter asking for a
`ReadWrite` scope, this is why: graph2otel never uses that scope to write any Intune configuration
or device state — it creates the export job, polls its status, and reads the exported result back.
No collector ever touches `DeviceManagementManagedDevices.PrivilegedOperations.All` (remote wipe and
other destructive actions) or any other write scope; this one `ReadWrite` grant, needed only by these
opt-in export collectors, is the sole exception to graph2otel's read-only posture. Because
these collectors are all opt-in (`Experimental`, see [`collectors.md`](./collectors.md)), a
default/read-only deployment never requests this scope at all.

## 4b. Some endpoints need a second, non-Graph registration (gotcha #4)

A granted Graph scope is not always sufficient. Purview eDiscovery
(`security/cases/ediscoveryCases`) returns **401 with `eDiscovery.Read.All` present in the
token** until the app's service principal is separately registered with the Security &
Compliance data plane via PowerShell. No Graph scope moves it — the data plane does not
know the principal, which is a different failure from a missing scope (that one 403s).

`graph2otel check` cannot detect this: it reports what is granted and consented, and the
grant is not the problem.

Only Purview eDiscovery (`purview.ediscovery_cases`, opt-in) needs this today. If you
enable it, see [`data-plane-registration.md`](./data-plane-registration.md) for the
procedure.

## 4c. One collector authenticates with a static token, not the Entra app (gotcha #5)

`mdca.discovery_parse` (#145) is the single exception to "every scope is a Graph app-role on
the poller." It reads the Microsoft Defender for Cloud Apps **Cloud Discovery governance log**,
which lives only on the legacy MDCA portal API
(`<tenant>.<region>.portal.cloudappsecurity.com`) — there is no Graph endpoint for it. That API
authenticates with a **static portal token** in an `Authorization: Token <secret>` header, NOT
`DefaultAzureCredential` and NOT a Graph token. So:

- There is **no Graph scope to grant** for it — `RequiredPermissions()` is empty, and
  `graph2otel check` neither lists nor verifies it (it has nothing to check against a Graph token).
- The token is supplied per-tenant via `mdca.token_file` (a filesystem PATH in config; the token
  itself is mounted as a file, never in YAML or env). Generate the token in the MDCA portal
  (Settings → Cloud Discovery → automatic log upload / API tokens) with the least-privilege scope
  your tenant offers.
- The collector is `Experimental` (opt-in): the portal API is a legacy surface with no Graph
  successor. Setting `mdca.portal_url` is the whole opt-in.

## 4d. Teams inventory uses an app-wide scope, not the narrower RSC one (gotcha #6)

`m365.teams` (#121) declares `Team.ReadBasic.All` (for `GET /teams`) and
`TeamSettings.Read.All` (for the per-team `GET /teams/{id}?$select=summary`). The
documented *least-privilege* scope for the summary is `TeamSettings.Read.Group`, but that
is **resource-specific consent (RSC)** — granted per team by installing a Teams app with an
RSC manifest into each team — which cannot serve a tenant-wide poller that must enumerate
every team it has never been installed in. `TeamSettings.Read.All` is the workable
application scope for a tenant-wide inventory, and is the deliberate (documented) deviation
from narrowest-scope here. The collector degrades to a skip-and-log if these are not granted,
so a 403 is a "not granted yet", not a crash.

## 5. Verify with `graph2otel check`

The `check` subcommand (landed as part of M1, tracked in
[#11](https://github.com/rknightion/graph2otel/issues/11)) is a read-only, side-effect-free
permission preflight: it loads your config, reads each configured tenant's granted permission claims
via a token, and reports what's missing against what your enabled collectors declare —
surfacing a 403 before you find it at runtime instead of after.

```sh
graph2otel check --config /path/to/config.yaml
```

Its help text (`graph2otel check -h`) also prints the least-privilege notes from this page (the
`ReadWrite` exception and the never-request list) and the two caveats it cannot verify by itself
(admin consent already granted vs. merely added; directory-role gating) — so it's a good first stop
when troubleshooting a 403.

**Known gap, as of this writing:** the composition root's collector-requirement wiring
(`requiredCollectorPermissions` in `cmd/graph2otel/check.go`) is still a placeholder returning no
requirements, left over from when `check` was built ahead of the M2–M5 collectors landing. Until
that wiring catches up to the registry of real collectors, `check` runs and prints its help text but
does not yet compare against any tenant's actually-enabled collectors — track this against the `#11`
follow-up rather than assuming per-collector enforcement is live today.

## Least-privilege summary

- Grant only the scopes your **enabled** collectors need (see [`collectors.md`](./collectors.md)) —
  a disabled collector makes zero Graph API calls and needs zero permission.
- Never grant `DeviceManagementManagedDevices.PrivilegedOperations.All` — graph2otel has no use for
  destructive device actions and never requests it.
- The one legitimate write-level exception is `DeviceManagementManagedDevices.ReadWrite.All`, and
  only if you enable one of the six export-report collectors.
- See `SECURITY.md` for the full data-handling and cardinality posture this permission model
  supports.
