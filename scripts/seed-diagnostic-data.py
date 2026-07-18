#!/usr/bin/env python3
"""seed-diagnostic-data — generate representative telemetry into the *thin* diagnostic
containers so graph2otel collectors can be built and tested against real wire data.

WHY THIS EXISTS
    On a small tenant many diagnostic categories are near-empty: the events they carry
    (Defender alerts, email flow, ID-Protection risk, Windows registry writes, ...) just
    don't happen often. But collector mappers on this project are written against LIVE
    samples, never docs or hand-written fixtures (see CLAUDE.md). This tool fires the
    safe, repeatable actions that make those events happen, so a container that has gone
    stale (retention is ~2 days) can be re-lit on demand before you sit down to build or
    debug its collector. Pair it with storage-report.py to confirm the bytes land.

    Container -> what this seeds it with:
      emailevents / emailurlinfo / emailattachmentinfo   a batch of varied emails
      riskyusers / userriskevents                        an adminConfirmedUserCompromised event
      alertinfo / alertevidence / deviceevents           EICAR AV detections (local + winsrv)
      deviceprocessevents                                the official MDE EDR detection test
      deviceregistryevents                               Windows Run-key create/modify/delete

AUTH  (same principle as storage-report.py — your creds, never the poller's)
    Graph app-only actions (email/risk/intune) need an app-only token. Rather than store
    one, this uses your local `az login` identity to spin up a SHORT-LIVED app registration
    (Mail.Send + IdentityRiskyUser.ReadWrite.All + Intune write), admin-consents it, does
    the work, and DELETES it again. Your `az` identity therefore needs Application.ReadWrite.All
    + AppRoleAssignment.ReadWrite.All + User.ReadWrite.All (a Global Admin / equivalent has these).
    The local EICAR pass needs `mdatp` (macOS MDE). The winsrv pass needs pywinrm + a Windows
    credential supplied via env (never hardcoded — see below).

USAGE
    scripts/seed-diagnostic-data.py --all              # every safe seeder + winsrv if creds present
    scripts/seed-diagnostic-data.py --emails           # just the email tables
    scripts/seed-diagnostic-data.py --risk             # just an ID-Protection risk event
    scripts/seed-diagnostic-data.py --eicar-local      # just EICAR on this Mac (needs mdatp)
    scripts/seed-diagnostic-data.py --winsrv           # EICAR + registry + EDR test on winsrv
    scripts/seed-diagnostic-data.py --intune           # Intune compliance-policy CRUD
    scripts/seed-diagnostic-data.py --dry-run --all    # print what it would do, touch nothing
    scripts/seed-diagnostic-data.py --cleanup          # delete any leftover g2o-seed-* apps/users

    Email target defaults to --to rob@decanha-knight.com from --from rob@m7kni.io (override both).
    winsrv creds come from env: G2O_WINSRV_HOST (default winsrv), G2O_WINSRV_USER (default
    administrator), G2O_WINSRV_PASS (required for --winsrv; if unset the winsrv pass is skipped).

CLEANUP
    The temp app is always deleted at the end of a run (even on error). The throwaway risk
    user is named g2o-seed-risk-<ts>-DELETE-ME and LEFT in place so its risk event has time
    to stream; `--cleanup` removes every g2o-seed-* app and user in one go.
"""
import argparse
import base64
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

GRAPH = "https://graph.microsoft.com/v1.0"
GRAPH_APPID = "00000003-0000-0000-c000-000000000000"
# application-permission (role) IDs on Microsoft Graph
ROLES = {
    "Mail.Send": "b633e1c5-b582-4048-a93e-9f11b44c7e96",
    "IdentityRiskyUser.ReadWrite.All": "656f6061-f9fe-4807-9708-6a2e0934df76",
    "DeviceManagementConfiguration.ReadWrite.All": "9241abd9-d0e6-425a-bd4f-47ba86e767a4",
}
EICAR = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def log(msg):
    print(msg, flush=True)


def die(msg):
    sys.exit(f"error: {msg}")


# ---------------------------------------------------------------- az / graph helpers
def az(*args, check=True):
    r = subprocess.run(["az", *args], capture_output=True, text=True)
    if check and r.returncode != 0:
        die(f"az {' '.join(args[:3])}...: {r.stderr.strip()[:300]}")
    return r


def az_json(*args):
    return json.loads(az(*args).stdout or "null")


def mgmt_token():
    r = az("account", "get-access-token", "--resource", "https://graph.microsoft.com",
           "--query", "accessToken", "-o", "tsv")
    return r.stdout.strip()


def gcall(method, path, token, body=None) -> "tuple[int, dict]":
    hdr = {"Authorization": "Bearer " + token, "Content-Type": "application/json"}
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(GRAPH + path, data=data, headers=hdr, method=method)
    try:
        r = urllib.request.urlopen(req, timeout=60)
        raw = r.read()
        return r.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        return e.code, {"error": e.read().decode(errors="replace")[:400]}


def app_token(appid, secret, tenant):
    data = urllib.parse.urlencode({
        "client_id": appid, "client_secret": secret,
        "scope": "https://graph.microsoft.com/.default",
        "grant_type": "client_credentials",
    }).encode()
    url = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
    last = ""
    for _ in range(8):  # wait out consent propagation
        try:
            r = urllib.request.urlopen(urllib.request.Request(url, data=data), timeout=30)
            return json.loads(r.read())["access_token"]
        except urllib.error.HTTPError as e:
            last = e.read().decode(errors="replace")[:200]
            time.sleep(8)
    die(f"could not get app token after consent: {last}")


# ---------------------------------------------------------------- temp app lifecycle
def create_temp_app(roles, mgmt):
    """Create app + SP + secret, admin-consent `roles`. Returns (appId, objId, secret)."""
    ra = [{"id": ROLES[r], "type": "Role"} for r in roles]
    rra = json.dumps([{"resourceAppId": GRAPH_APPID, "resourceAccess": ra}])
    app = az_json("ad", "app", "create", "--display-name", "g2o-seed-temp",
                  "--sign-in-audience", "AzureADMyOrg", "--required-resource-accesses", rra, "-o", "json")
    appid, objid = app["appId"], app["id"]
    sp_obj = az("ad", "sp", "create", "--id", appid, "--query", "id", "-o", "tsv").stdout.strip()
    secret = az("ad", "app", "credential", "reset", "--id", appid, "--append",
                "--years", "1", "--query", "password", "-o", "tsv").stdout.strip()
    graph_sp = az("ad", "sp", "show", "--id", GRAPH_APPID, "--query", "id", "-o", "tsv").stdout.strip()
    for r in roles:
        st, resp = gcall("POST", f"/servicePrincipals/{sp_obj}/appRoleAssignments", mgmt,
                         {"principalId": sp_obj, "resourceId": graph_sp, "appRoleId": ROLES[r]})
        if st >= 300:
            log(f"  ! consent {r} failed: {resp.get('error')}")
    log(f"  temp app {appid} created + consented ({', '.join(roles)})")
    return appid, objid, secret


def delete_app(appid):
    az("ad", "app", "delete", "--id", appid, check=False)
    log(f"  temp app {appid} deleted")


# ---------------------------------------------------------------- seeders
def seed_emails(tok, sender, rcpt, dry):
    log("=== emails ===")
    pdf = (b"%PDF-1.1\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids"
           b"[3 0 R]/Count 1>>endobj\n3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 200 200]>>"
           b"endobj\nxref\n0 4\ntrailer<</Root 1 0 R/Size 4>>\n%%EOF")
    gif = base64.b64decode("R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw==")
    msgs = [
        ("g2o seed: quarterly report link", "<p>Review the <a href='https://www.example.com/q3'>Q3 report</a> and <a href='http://example.org/x'>appendix</a>.</p>", None),
        ("g2o seed: invoice attached", "<p>Invoice attached. <a href='https://portal.example.net/pay'>pay</a>.</p>", ("invoice.pdf", "application/pdf", pdf)),
        ("g2o seed: meeting notes", "<p>Notes attached. <a href='https://teams.example.com/rec'>recording</a>.</p>", ("notes.txt", "text/plain", b"seed notes")),
        ("g2o seed: newsletter", "<p><a href='https://a.example.com'>a</a> <a href='https://b.example.com'>b</a> <a href='https://c.example.com'>c</a></p>", None),
        ("g2o seed: shipping confirmation", "<p><a href='https://track.example.com/xyz'>track</a>.</p>", None),
        ("g2o seed: doc share", "<p>Doc attached.</p>", ("spec.txt", "text/plain", b"seed spec")),
        ("g2o seed: security notice", "<p>Reset via <a href='https://login.example.com/reset'>link</a>.</p>", None),
        ("g2o seed: photo attached", "<p>Image attached.</p>", ("pixel.gif", "image/gif", gif)),
        ("g2o seed: plain text no link", "<p>Plain internal message.</p>", None),
        ("g2o seed: archive attached", "<p>Archive attached.</p>", ("bundle.zip", "application/zip", b"PK\x03\x04seed")),
    ]
    if dry:
        log(f"  DRY: would send {len(msgs)} emails {sender} -> {rcpt}\n")
        return
    sent = 0
    for subj, html, att in msgs:
        m = {"subject": subj, "body": {"contentType": "HTML", "content": html},
             "toRecipients": [{"emailAddress": {"address": rcpt}}]}
        if att:
            n, ct, c = att
            m["attachments"] = [{"@odata.type": "#microsoft.graph.fileAttachment",
                                 "name": n, "contentType": ct, "contentBytes": base64.b64encode(c).decode()}]
        st, resp = gcall("POST", f"/users/{sender}/sendMail", tok, {"message": m, "saveToSentItems": True})
        sent += st < 300
        if st >= 300:
            log(f"  ! {subj[:36]}: {resp.get('error')}")
        time.sleep(1)
    log(f"  sent {sent}/{len(msgs)} emails {sender} -> {rcpt}\n")


def seed_risk(tok, mgmt, tenant, dry):
    log("=== risk (adminConfirmedUserCompromised) ===")
    ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    upn = f"g2o-seed-risk-{ts}-DELETE-ME@{onmicrosoft_domain(tenant)}"
    if dry:
        log(f"  DRY: would create {upn}, confirmCompromised, leave for streaming\n")
        return
    pw = "G2o!" + base64.urlsafe_b64encode(os.urandom(9)).decode().rstrip("=")
    st, resp = gcall("POST", "/users", mgmt, {
        "accountEnabled": True, "displayName": "g2o seed risk", "mailNickname": f"g2o-seed-risk-{ts}",
        "userPrincipalName": upn,
        "passwordProfile": {"forceChangePasswordNextSignIn": False, "password": pw}})
    if st >= 300:
        log(f"  ! create user: {resp.get('error')}\n")
        return
    uid = resp["id"]
    st2, resp2 = gcall("POST", "/identityProtection/riskyUsers/confirmCompromised", tok, {"userIds": [uid]})
    if st2 < 300:
        log(f"  confirmed compromised: {upn} (left in place; --cleanup to remove)\n")
    else:
        log(f"  ! confirmCompromised: {resp2.get('error')}\n")


def seed_intune(tok, dry):
    log("=== intune compliance-policy CRUD (operational/audit) ===")
    if dry:
        log("  DRY: would create+assign+delete a windows10CompliancePolicy\n")
        return
    pol = {"@odata.type": "#microsoft.graph.windows10CompliancePolicy",
           "displayName": "g2o-seed-temp-compliance", "description": "temp seed - safe to delete",
           "passwordRequired": False, "osMinimumVersion": "10.0.19041.0",
           "scheduledActionsForRule": [{"ruleName": "PasswordRequired", "scheduledActionConfigurations":
               [{"actionType": "block", "gracePeriodHours": 72, "notificationTemplateId": ""}]}]}
    # the manage.microsoft.com proxy caches app perms far longer than the token endpoint, so a
    # freshly-consented app 403s here for a minute or two — retry through the propagation window.
    pid = None
    for attempt in range(8):
        st, resp = gcall("POST", "/deviceManagement/deviceCompliancePolicies", tok, pol)
        pid = resp.get("id")
        if pid:
            break
        if "Forbidden" in str(resp.get("error", "")) and attempt < 7:
            time.sleep(15)
            continue
        log(f"  ! create policy: {resp.get('error')}\n")
        return
    if not pid:
        return
    gcall("POST", f"/deviceManagement/deviceCompliancePolicies/{pid}/assign", tok,
          {"assignments": [{"target": {"@odata.type": "#microsoft.graph.allDevicesAssignmentTarget"}}]})
    time.sleep(2)
    gcall("DELETE", f"/deviceManagement/deviceCompliancePolicies/{pid}", tok)
    log("  policy created+assigned+deleted\n")


def seed_eicar_local(dry):
    log("=== EICAR on this host (local MDE) ===")
    import shutil
    if not shutil.which("mdatp"):
        log("  skip: mdatp not present (not a macOS MDE-onboarded host)\n")
        return
    if dry:
        log("  DRY: would drop 3 EICAR files + 1 network download for RTP to quarantine\n")
        return
    import tempfile
    d = tempfile.mkdtemp()
    for i in range(1, 4):
        try:
            with open(os.path.join(d, f"g2o_eicar_{i}.com"), "w") as f:
                f.write(EICAR)
        except OSError:
            pass
    # the network-download variant is a more reliable trigger than a local write (RTP scans the
    # download); local writes of identical test content can get cloud-cached and skip a detection.
    subprocess.run(["curl", "-s", "-m", "15", "-o", os.path.join(d, "g2o_dl.com"),
                    "https://secure.eicar.org/eicar.com.txt"], capture_output=True)
    time.sleep(3)
    # macOS RTP scans asynchronously, so file-still-present != not-detected — report what mdatp saw.
    import shutil as _sh
    tl = subprocess.run(["mdatp", "threat", "list"], capture_output=True, text=True).stdout if _sh.which("mdatp") else ""
    recent = tl.count("EICAR") if tl else 0
    log(f"  dropped 3 EICAR files + 1 download; mdatp reports {recent} EICAR detection(s) on record")
    log("  (RTP is async — confirm the alert bytes via storage-report.py)\n")


def seed_winsrv(dry):
    log("=== winsrv (EICAR + registry + EDR test over WinRM) ===")
    host = os.environ.get("G2O_WINSRV_HOST", "winsrv")
    user = os.environ.get("G2O_WINSRV_USER", "administrator")
    pw = os.environ.get("G2O_WINSRV_PASS")
    if not pw:
        log("  skip: set G2O_WINSRV_PASS (and optionally G2O_WINSRV_HOST/USER) to seed winsrv\n")
        return
    if dry:
        log(f"  DRY: would WinRM to {user}@{host}: EICAR x3 + Run-key CRUD + MDE detection test\n")
        return
    try:
        import winrm  # type: ignore
    except ImportError:
        log("  skip: pywinrm not installed (pip install pywinrm)\n")
        return
    s = winrm.Session(f"http://{host}:5985/wsman", auth=(user, pw), transport="ntlm")
    script = r"""
$e = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
$enc = New-Object System.Text.ASCIIEncoding
foreach ($n in 1..3) { [System.IO.File]::WriteAllText((Join-Path $env:TEMP "g2o_av_$n.com"), $e, $enc) }
$ErrorActionPreference='SilentlyContinue'
(New-Object System.Net.WebClient).DownloadFile('http://127.0.0.1/1.exe', (Join-Path $env:TEMP 'g2o-test.exe'))
Start-Process (Join-Path $env:TEMP 'g2o-test.exe')
$k='HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
New-ItemProperty $k -Name g2oSeed -Value 'C:\seed\a.exe' -PropertyType String -Force | Out-Null
Set-ItemProperty  $k -Name g2oSeed -Value 'C:\seed\b.exe'
Remove-ItemProperty $k -Name g2oSeed
Start-Sleep -Seconds 3
Remove-Item "$env:TEMP\g2o_av_*.com","$env:TEMP\g2o-test.exe" -ErrorAction SilentlyContinue
"winsrv seed done: EICAR x3 + registry CRUD + EDR test"
"""
    r = s.run_ps(script)
    log("  " + (r.std_out.decode(errors="replace").strip() or f"rc={r.status_code}") + "\n")


def cleanup(mgmt):
    log("=== cleanup: removing g2o-seed-* apps and users ===")
    apps = az_json("ad", "app", "list", "--filter", "startswith(displayName,'g2o-seed')",
                   "--query", "[].{id:appId,name:displayName}", "-o", "json") or []
    for a in apps:
        az("ad", "app", "delete", "--id", a["id"], check=False)
        log(f"  deleted app {a['name']} ({a['id']})")
    st, resp = gcall("GET", "/users?$filter=startswith(userPrincipalName,'g2o-seed')&$select=id,userPrincipalName", mgmt)
    for u in resp.get("value", []) if st < 300 else []:
        gcall("DELETE", f"/users/{u['id']}", mgmt)
        log(f"  deleted user {u['userPrincipalName']}")
    log("  cleanup done\n")


# ---------------------------------------------------------------- misc
def onmicrosoft_domain(tenant):
    doms = az_json("rest", "--method", "get", "--url",
                   f"{GRAPH}/domains?$select=id,isInitial") or {}
    for d in doms.get("value", []):
        if d.get("isInitial"):
            return d["id"]
    return "onmicrosoft.com"


def main():
    ap = argparse.ArgumentParser(description="Seed representative telemetry into thin diagnostic containers.")
    ap.add_argument("--all", action="store_true", help="run every safe seeder (+ winsrv if creds present)")
    ap.add_argument("--emails", action="store_true")
    ap.add_argument("--risk", action="store_true")
    ap.add_argument("--intune", action="store_true")
    ap.add_argument("--eicar-local", action="store_true")
    ap.add_argument("--winsrv", action="store_true")
    ap.add_argument("--cleanup", action="store_true", help="delete leftover g2o-seed-* apps/users and exit")
    ap.add_argument("--from", dest="sender", default="rob@m7kni.io")
    ap.add_argument("--to", dest="rcpt", default="rob@decanha-knight.com")
    ap.add_argument("--dry-run", action="store_true", help="print actions, touch nothing")
    args = ap.parse_args()

    acct = az_json("account", "show", "-o", "json")
    tenant = acct["tenantId"]
    log(f"tenant {tenant} · signed in as {acct['user']['name']}\n")
    mgmt = mgmt_token()

    if args.cleanup:
        cleanup(mgmt)
        return

    do_emails = args.emails or args.all
    do_risk = args.risk or args.all
    do_intune = args.intune or args.all
    do_local = args.eicar_local or args.all
    do_winsrv = args.winsrv or args.all
    if not any([do_emails, do_risk, do_intune, do_local, do_winsrv]):
        ap.error("nothing to do — pass --all or one of --emails/--risk/--intune/--eicar-local/--winsrv")

    # device-side seeders need no Graph app
    if do_local:
        seed_eicar_local(args.dry_run)
    if do_winsrv:
        seed_winsrv(args.dry_run)

    # graph app-only seeders share one short-lived app
    if do_emails or do_risk or do_intune:
        roles = []
        if do_emails:
            roles.append("Mail.Send")
        if do_risk:
            roles.append("IdentityRiskyUser.ReadWrite.All")
        if do_intune:
            roles.append("DeviceManagementConfiguration.ReadWrite.All")
        if args.dry_run:
            log(f"=== graph app (DRY, not created): roles {roles} ===")
            if do_emails:
                seed_emails(None, args.sender, args.rcpt, True)
            if do_risk:
                seed_risk(None, None, tenant, True)
            if do_intune:
                seed_intune(None, True)
        else:
            appid, _objid, secret = create_temp_app(roles, mgmt)
            try:
                tok = app_token(appid, secret, tenant)
                if do_emails:
                    seed_emails(tok, args.sender, args.rcpt, False)
                if do_risk:
                    seed_risk(tok, mgmt, tenant, False)
                if do_intune:
                    seed_intune(tok, False)
            finally:
                delete_app(appid)

    log("done — run scripts/storage-report.py in ~15 min to confirm the bytes landed.")


if __name__ == "__main__":
    main()
