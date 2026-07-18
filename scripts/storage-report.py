#!/usr/bin/env python3
"""storage-report — size every blob container in the graph2otel diagnostic-settings
storage account, rank them largest-first, and track growth over time.

WHY THIS EXISTS
    graph2otel reads Azure Monitor diagnostic-settings output (Entra sign-ins,
    MicrosoftGraphActivityLogs, Intune, Defender XDR advanced-hunting streaming, ...)
    out of one Storage account. Diagnostic categories are cheap to switch on and easy
    to forget, and the Defender XDR "advanced hunting" tables in particular can dwarf
    everything else. This tells you, on demand, exactly where the bytes are and how
    fast each container is growing, so you can decide what to keep streaming.

AUTH
    Uses your local `az login` identity — no poller credentials are copied anywhere.
    Container/blob listing is a DATA-plane operation, so it needs `Storage Blob Data
    Reader` (or Owner+data role) on the account. If AAD listing is denied, the script
    falls back to the account key (fetched via `az storage account keys list`, which an
    account Owner can do) — pass --use-key to force that path.

USAGE
    scripts/storage-report.py                       # size + report, record a snapshot
    scripts/storage-report.py --top 15              # only the 15 largest
    scripts/storage-report.py --no-record           # don't append to history
    scripts/storage-report.py --html /tmp/rep.html  # also write a standalone HTML report
    scripts/storage-report.py --account otheracct   # a different storage account
    scripts/storage-report.py --json                # machine-readable snapshot to stdout

    Growth appears automatically once there are >=2 snapshots in the history file
    (default ~/.local/state/graph2otel/storage-history.jsonl). Run it on a cron/launchd
    timer (say hourly or daily) to build a real growth curve.

Depends only on: python3 stdlib + the Azure CLI (`az`) on PATH.
"""
from __future__ import annotations
import argparse, json, os, subprocess, sys, time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

DEFAULT_ACCOUNT = os.environ.get("G2O_STORAGE_ACCOUNT", "graph2otelm7kni")
DEFAULT_HISTORY = os.environ.get(
    "G2O_STORAGE_HISTORY",
    os.path.expanduser("~/.local/state/graph2otel/storage-history.jsonl"),
)

# ----- terminal colour (auto-off when not a tty or NO_COLOR set) -------------
_TTY = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
def c(code: str, s: str) -> str:
    return f"\033[{code}m{s}\033[0m" if _TTY else s
BOLD = lambda s: c("1", s)
DIM = lambda s: c("2", s)
CYAN = lambda s: c("36", s)
GREEN = lambda s: c("32", s)
YELLOW = lambda s: c("33", s)
RED = lambda s: c("31", s)


def az(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(["az", *args], capture_output=True, text=True)


def require_az() -> None:
    if az(["account", "show", "-o", "none"]).returncode != 0:
        sys.exit("Not logged in to Azure CLI. Run:  az login")


def account_key(account: str) -> str | None:
    r = az(["storage", "account", "keys", "list", "--account-name", account,
            "--query", "[0].value", "-o", "tsv"])
    return r.stdout.strip() if r.returncode == 0 and r.stdout.strip() else None


def auth_flags(account: str, use_key: bool) -> tuple[list[str], str]:
    """Return (az storage auth flags, human label). Try AAD first; fall back to key."""
    if not use_key:
        probe = az(["storage", "container", "list", "--account-name", account,
                    "--auth-mode", "login", "--num-results", "1", "-o", "none"])
        if probe.returncode == 0:
            return ["--auth-mode", "login"], "AAD (az login identity)"
        # AAD denied or failed — fall through to key
    key = account_key(account)
    if not key:
        sys.exit(
            f"Cannot list '{account}' via AAD and cannot read an account key.\n"
            "Grant your identity 'Storage Blob Data Reader' on the account, or ensure "
            "you have rights to list account keys.")
    return ["--account-key", key, "--auth-mode", "key"], "account key (fallback)"


def list_containers(account: str, flags: list[str]) -> list[str]:
    r = az(["storage", "container", "list", "--account-name", account, *flags,
            "--query", "[].name", "-o", "json"])
    if r.returncode != 0:
        sys.exit(f"Failed to list containers:\n{r.stderr.strip()}")
    return sorted(json.loads(r.stdout or "[]"))


def size_container(account: str, flags: list[str], name: str) -> dict:
    r = az(["storage", "blob", "list", "--account-name", account, "--container-name", name,
            *flags, "--query", "[].{s:properties.contentLength,m:properties.lastModified}",
            "-o", "json"])
    if r.returncode != 0:
        return {"name": name, "bytes": 0, "blobs": 0, "newest": None, "error": r.stderr.strip()[:200]}
    rows = json.loads(r.stdout or "[]")
    total = sum(int(x.get("s") or 0) for x in rows)
    newest = max((x.get("m") for x in rows if x.get("m")), default=None)
    return {"name": name, "bytes": total, "blobs": len(rows), "newest": newest}


# ----- formatting helpers ----------------------------------------------------
def human(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1024:
            return f"{n:,.0f} {unit}" if unit == "B" else f"{n:,.1f} {unit}"
        n /= 1024
    return f"{n:,.1f} TB"


def human_signed(n: float) -> str:
    return ("+" if n >= 0 else "-") + human(abs(n))


def age(iso: str | None) -> str:
    if not iso:
        return "-"
    try:
        t = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return "-"
    secs = (datetime.now(timezone.utc) - t).total_seconds()
    if secs < 3600:
        return f"{secs/60:.0f}m"
    if secs < 86400:
        return f"{secs/3600:.1f}h"
    return f"{secs/86400:.1f}d"


def load_history(path: str) -> list[dict]:
    if not os.path.exists(path):
        return []
    out = []
    for line in open(path):
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return out


def record_snapshot(path: str, snap: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a") as f:
        f.write(json.dumps(snap) + "\n")


def prev_for(hist: list[dict], account: str) -> dict | None:
    for snap in reversed(hist):
        if snap.get("account") == account:
            return snap
    return None


def oldest_for(hist: list[dict], account: str) -> dict | None:
    for snap in hist:
        if snap.get("account") == account:
            return snap
    return None


# Below this span the oldest snapshot is too recent to extrapolate a daily rate
# from without producing nonsense (a 1-minute gap would imply GB/day from a few KB).
MIN_RATE_SPAN_DAYS = 1 / 24  # 1 hour


def per_day(cur_bytes: int, base: dict | None, name: str) -> float | None:
    """Bytes/day growth for one container between the oldest snapshot and now.
    Returns None until at least MIN_RATE_SPAN_DAYS have elapsed, so short-interval
    reruns don't display wildly extrapolated rates."""
    if not base:
        return None
    base_bytes = base.get("containers", {}).get(name, {}).get("bytes")
    if base_bytes is None:
        return None
    days = (time.time() - base.get("epoch", 0)) / 86400
    if days < MIN_RATE_SPAN_DAYS:
        return None
    return (cur_bytes - base_bytes) / days


# ----- report rendering ------------------------------------------------------
def render_terminal(account: str, rows: list[dict], prev: dict | None,
                    oldest: dict | None, auth_label: str, top: int | None) -> None:
    total = sum(r["bytes"] for r in rows)
    total_blobs = sum(r["blobs"] for r in rows)
    shown = rows[:top] if top else rows
    biggest = max((r["bytes"] for r in rows), default=1) or 1
    barw = 24

    print()
    print(BOLD(f"  graph2otel storage — {account}"))
    print(DIM(f"  {len(rows)} containers · {human(total)} · {total_blobs:,} blobs · "
              f"auth: {auth_label} · {datetime.now().strftime('%Y-%m-%d %H:%M')}"))
    if prev:
        dt_h = (time.time() - prev.get("epoch", 0)) / 3600
        d_bytes = total - prev.get("totals", {}).get("bytes", 0)
        print(DIM(f"  since last snapshot ({dt_h:.1f}h ago): ") +
              (GREEN if d_bytes >= 0 else RED)(human_signed(d_bytes)))
    print()

    hdr = f"  {'CONTAINER':<44}{'SIZE':>11}  {'%':>5}  {'BAR':<{barw}} {'BLOBS':>6} {'AGE':>6} {'Δ/DAY':>11}"
    print(BOLD(hdr))
    print(DIM("  " + "-" * (len(hdr) - 2)))
    for r in shown:
        pct = 100 * r["bytes"] / total if total else 0
        fill = int(barw * r["bytes"] / biggest)
        bar = "█" * fill + "·" * (barw - fill)
        rate = per_day(r["bytes"], oldest, r["name"])
        rate_s = "-" if rate is None else human_signed(rate)
        rate_c = DIM(rate_s) if rate is None else (GREEN if rate >= 0 else RED)(rate_s)
        name = r["name"].replace("insights-logs-", "")
        big = r["bytes"] >= 20 * 1024**2
        name_c = (YELLOW if big else CYAN)(f"{name:<44.44}")
        print(f"  {name_c}{human(r['bytes']):>11}  {pct:>4.1f}%  {bar:<{barw}} "
              f"{r['blobs']:>6} {age(r['newest']):>6} {rate_c:>11}")
    if top and len(rows) > top:
        rest = sum(r["bytes"] for r in rows[top:])
        print(DIM(f"  … {len(rows)-top} more containers, {human(rest)}"))
    print(DIM("  " + "-" * (len(hdr) - 2)))
    total_label = f"{'TOTAL':<44}"
    print("  " + BOLD(total_label) + BOLD(f"{human(total):>11}"))
    print(DIM("  yellow = >=20MB (high-volume) · Δ/DAY needs >=2 snapshots spanning time\n"))


def render_html(path: str, account: str, rows: list[dict], prev: dict | None,
                oldest: dict | None) -> None:
    total = sum(r["bytes"] for r in rows) or 1
    biggest = max((r["bytes"] for r in rows), default=1) or 1
    trs = []
    for r in rows:
        pct = 100 * r["bytes"] / total
        w = 100 * r["bytes"] / biggest
        rate = per_day(r["bytes"], oldest, r["name"])
        rate_s = "—" if rate is None else human_signed(rate)
        big = r["bytes"] >= 20 * 1024**2
        name = r["name"].replace("insights-logs-", "")
        trs.append(
            f"<tr><td class='n'>{name}{' <span class=hi>HV</span>' if big else ''}</td>"
            f"<td class='num'>{human(r['bytes'])}</td><td class='num'>{pct:.1f}%</td>"
            f"<td class='bar'><span style='width:{w:.1f}%'></span></td>"
            f"<td class='num'>{r['blobs']:,}</td><td class='num'>{rate_s}</td></tr>")
    since = ""
    if prev:
        d = sum(r["bytes"] for r in rows) - prev.get("totals", {}).get("bytes", 0)
        dt_h = (time.time() - prev.get("epoch", 0)) / 3600
        since = f"<p class='sub'>Since last snapshot ({dt_h:.1f}h ago): <b>{human_signed(d)}</b></p>"
    html = f"""<!doctype html><meta charset=utf-8><title>graph2otel storage — {account}</title>
<style>
 body{{font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;margin:2rem;background:#0d1117;color:#e6edf3}}
 h1{{font-size:1.2rem;margin:0}} .sub{{color:#8b949e;margin:.2rem 0 1rem}}
 table{{border-collapse:collapse;width:100%;max-width:1000px}}
 th,td{{padding:.35rem .6rem;border-bottom:1px solid #21262d;text-align:left}}
 th{{color:#8b949e;font-weight:600;font-size:.8rem;text-transform:uppercase;letter-spacing:.04em}}
 .num{{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}}
 .n{{font-family:ui-monospace,Menlo,monospace}}
 .bar{{width:30%}} .bar span{{display:block;height:12px;border-radius:3px;background:linear-gradient(90deg,#1f6feb,#388bfd)}}
 .hi{{background:#9e6a03;color:#fff;font-size:.65rem;padding:0 .3rem;border-radius:3px;vertical-align:middle}}
 tfoot td{{font-weight:700;border-top:2px solid #30363d}}
</style>
<h1>graph2otel storage — {account}</h1>
<p class=sub>{len(rows)} containers · {human(total)} total · {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
{since}
<table><thead><tr><th>Container</th><th class=num>Size</th><th class=num>%</th>
<th>Share</th><th class=num>Blobs</th><th class=num>Δ/day</th></tr></thead>
<tbody>{''.join(trs)}</tbody>
<tfoot><tr><td>TOTAL</td><td class=num>{human(total)}</td><td colspan=4></td></tr></tfoot></table>
<p class=sub>HV = high-volume (&ge;20&nbsp;MB). Δ/day computed from the oldest recorded snapshot.</p>
"""
    open(path, "w").write(html)


def main() -> None:
    ap = argparse.ArgumentParser(description="Size + track graph2otel blob-storage containers.")
    ap.add_argument("--account", default=DEFAULT_ACCOUNT, help=f"storage account name (default {DEFAULT_ACCOUNT})")
    ap.add_argument("--history", default=DEFAULT_HISTORY, help="snapshot history JSONL path")
    ap.add_argument("--top", type=int, help="only show the N largest containers")
    ap.add_argument("--use-key", action="store_true", help="force account-key auth (skip AAD)")
    ap.add_argument("--no-record", action="store_true", help="do not append a snapshot to history")
    ap.add_argument("--html", metavar="PATH", help="also write a standalone HTML report")
    ap.add_argument("--json", action="store_true", help="print the snapshot as JSON (no table)")
    args = ap.parse_args()

    require_az()
    flags, auth_label = auth_flags(args.account, args.use_key)
    names = list_containers(args.account, flags)
    if not names:
        sys.exit(f"No containers found in '{args.account}'.")

    with ThreadPoolExecutor(max_workers=12) as ex:
        rows = list(ex.map(lambda n: size_container(args.account, flags, n), names))
    rows.sort(key=lambda r: r["bytes"], reverse=True)

    hist = load_history(args.history)
    prev = prev_for(hist, args.account)
    oldest = oldest_for(hist, args.account)

    snap = {
        "epoch": time.time(),
        "iso": datetime.now(timezone.utc).isoformat(),
        "account": args.account,
        "totals": {"bytes": sum(r["bytes"] for r in rows), "blobs": sum(r["blobs"] for r in rows)},
        "containers": {r["name"]: {"bytes": r["bytes"], "blobs": r["blobs"]} for r in rows},
    }

    if args.json:
        print(json.dumps(snap, indent=2))
    else:
        render_terminal(args.account, rows, prev, oldest, auth_label, args.top)
        errs = [r for r in rows if r.get("error")]
        if errs:
            print(RED(f"  {len(errs)} container(s) errored:"))
            for r in errs:
                print(RED(f"    {r['name']}: {r['error']}"))

    if args.html:
        render_html(args.html, args.account, rows, prev, oldest)
        if not args.json:
            print(DIM(f"  HTML report written to {args.html}\n"))

    if not args.no_record:
        record_snapshot(args.history, snap)


if __name__ == "__main__":
    main()
