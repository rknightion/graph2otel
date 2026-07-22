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

COST MODELLING (what-if scenarios — all overridable, none change what's measured)
    The billable AppendBlock count is READ FROM AZURE MONITOR, not guessed: the
    `Transactions` metric filtered to `ApiName eq 'AppendBlock'` is an exact count of
    billable append operations (an append blob supports no other write). `Ingress` over
    the same window calibrates the mean append size (Ingress / AppendBlock) instead of
    assuming one. The account-wide op count is then allocated across containers by byte
    share, and the scenario knobs re-price that measured rate under different
    assumptions:

    --retention-days D          actual lifecycle delete age (measurement anchor;
                                default: auto-detected from the account policy)
    --model-retention-days D    what-if retention to price against (storage scales
                                with it, write-ops don't) — e.g. "what if I kept 7d?"
    --volume-scale X            scale ALL activity by X (2.0 = double traffic/polls)
    --scale NAME=X              scale one container (substring match), repeatable —
                                e.g. --scale graphactivity=0.5 models halving
                                graph2otel's own Graph poll frequency (MGAL is ~60%
                                graph2otel's own calls, so this is a real lever)
    --metrics-days N            days of Azure Monitor history to average the measured
                                op rate over (default 3; whole UTC days only, today
                                excluded — a part-day drags the average down)
    --no-metrics                skip Azure Monitor and fall back to the modelled
                                estimate (see ACCURACY below)
    --price-storage-gb-mo / --price-write-10k / --price-read-10k /
    --avg-append-bytes          meter overrides

    When any knob is set the report switches to "modelled" mode and prints the new
    total, the delta vs measured-today, and which knobs are active. With no knobs
    (or model_retention==actual and scale==1) it reproduces the measured number
    exactly.

    Worked examples (shape, not current figures — rerun for live numbers):
      # model 7-day retention + halve graph2otel's own poll frequency
      scripts/storage-report.py --model-retention-days 7 --scale graphactivity=0.5
      # model turning cloudappevents off and dropping to 1-day retention
      scripts/storage-report.py --scale cloudappevents=0 --model-retention-days 1
      # model doubling all activity
      scripts/storage-report.py --volume-scale 2   (near-linear: writes dominate)

    The honest lesson the model makes visible: RETENTION IS NEARLY FREE, VOLUME IS
    THE BILL. Resident storage is pennies; the cost is AppendBlock write-ops, which
    scale with tenant activity and — for MicrosoftGraphActivityLogs — with
    graph2otel's own poll frequency. So the real levers are "which high-churn tables
    do I stream" and "how often do I poll", not "how long do I keep the data".

ACCURACY (what is measured vs what is allocated) — #228
    MEASURED, exactly: the account-wide AppendBlock / ListBlobs / PutBlob / GetBlob
    counts and the ingress bytes, straight off the Azure Monitor meters that Cost
    Management bills from. The mean append size is derived from those, never assumed.

    ALLOCATED, approximately: the split of those account-wide op counts across
    containers, by resident-byte share. The `Transactions` metric has NO container
    dimension, so a per-container op count is not obtainable. Byte-share allocation
    UNDER-attributes containers that write small records (the Entra categories, ~7 KB
    per append) and OVER-attributes ones that batch large (the Defender advanced-hunting
    tables). Account totals are right; per-row splits are indicative.

    FALLBACK: with --no-metrics, or when the Monitor call is denied (needs `Monitoring
    Reader` on the account) or returns no data, the old model runs instead —
    bytes / (avg_append * actual_retention) — and the report says MODELLED in red.
    That path is only as good as --avg-append-bytes, and the historic 7300 B default
    (measured on Entra categories alone, #137) came out 4.9x low once the Defender
    tables started streaming, over-stating the bill ~4.7x. Treat the fallback as an
    order-of-magnitude sanity check, not a cost estimate.

    NOT MODELLED: the Azure free-account 12-month grant. At real volume it is worth
    ~£0.35/month (10K free writes, 20K free list, 20K free reads, 5 GB stored, 15 GB
    egress) against a bill dominated by millions of writes — under 3%, and every
    meter that matters is already past its allowance. [live-measured 2026-07-22, #228]

    Growth appears automatically once there are >=2 snapshots in the history file
    (default ~/.local/state/graph2otel/storage-history.jsonl). Run it on a cron/launchd
    timer (say hourly or daily) to build a real growth curve.

Depends only on: python3 stdlib + the Azure CLI (`az`) on PATH.
"""
from __future__ import annotations
import argparse, json, os, subprocess, sys, time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

DEFAULT_ACCOUNT = os.environ.get("G2O_STORAGE_ACCOUNT", "graph2otelm7kni")
DEFAULT_HISTORY = os.environ.get(
    "G2O_STORAGE_HISTORY",
    os.path.expanduser("~/.local/state/graph2otel/storage-history.jsonl"),
)

# ----- pricing defaults --------------------------------------------------------
# Azure Blob Storage, uksouth, StorageV2 / Standard_LRS / Hot — the account this
# tool targets. Prices in GBP, from docs/blob-ingest.md's live-priced meters
# (#89/#137). Override any of them with the --price-* flags for a different
# account type/region. The bill is dominated by WRITE operations (AppendBlock),
# not resident storage — one endpoint's diagnostic stream is ~pennies of storage
# but pounds of append-op charges — so both are estimated and shown.
#
# The write price is confirmed against the live bill: Cost Management billed
# 32.7743 units of the "Hot LRS Write Operations" meter at £1.4650, i.e. exactly
# £0.0447 per 10K. [live-measured 2026-07-22, #228]
PRICE_STORAGE_GB_MONTH = 0.0145   # £/GiB-month, Hot LRS
PRICE_WRITE_PER_10K = 0.0447      # £/10k write ops (AppendBlock, PutBlob; listing bills at this rate too)
PRICE_READ_PER_10K = 0.0036       # £/10k read ops (GetBlob) — an order of magnitude cheaper
AVG_APPEND_BYTES = 7300           # FALLBACK ONLY — see ACCURACY above. Normally calibrated live.
DEFAULT_RETENTION_DAYS = 2        # lifecycle delete age; auto-detected when possible
DEFAULT_METRIC_DAYS = 3           # whole UTC days of Monitor history to average the op rate over
DAYS_PER_MONTH = 30.44
GIB = 1024 ** 3

# Azure Monitor `Transactions` ApiName values, bucketed by how each one bills.
# DeleteBlob is deliberately absent: blob deletes are not a billable operation.
WRITE_API_NAMES = ("PutBlob", "PutBlock", "PutBlockList", "SetBlobProperties", "SetBlobMetadata")
LIST_API_NAMES = ("ListBlobs", "ListContainers", "CreateContainer")
READ_API_NAMES = ("GetBlob", "GetBlobProperties", "GetBlobMetadata")

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


def account_ids(account: str) -> tuple[str | None, str | None]:
    """(resourceGroup, full resource id) for the storage account, or (None, None)."""
    r = az(["storage", "account", "show", "--name", account,
            "--query", "{rg:resourceGroup,id:id}", "-o", "json"])
    if r.returncode != 0 or not r.stdout.strip():
        return None, None
    try:
        d = json.loads(r.stdout)
    except json.JSONDecodeError:
        return None, None
    return d.get("rg"), d.get("id")


def detect_retention_days(account: str, rg: str | None) -> int | None:
    """Read the lifecycle delete age (daysAfterModificationGreaterThan) from the
    account's management policy. With the measured path this only anchors the
    STORAGE side of the model (the op count is read off the meter, not inferred);
    on the fallback path it still drives the whole estimate. None if unreadable."""
    if not rg:
        return None
    r = az(["storage", "account", "management-policy", "show", "--account-name", account, "-g", rg,
            "--query", "policy.rules[].definition.actions.baseBlob.delete.daysAfterModificationGreaterThan", "-o", "json"])
    if r.returncode != 0 or not r.stdout.strip():
        return None
    try:
        days = [int(d) for d in json.loads(r.stdout) if d is not None]
    except (json.JSONDecodeError, ValueError, TypeError):
        return None
    return min(days) if days else None


# ----- measured op rates (Azure Monitor) --------------------------------------
def metric_window(days: int, now_epoch: float | None = None) -> tuple[str, str]:
    """(start, end) ISO-Z bounds covering the last `days` WHOLE UTC days, ending at
    the most recent UTC midnight. Today is excluded on purpose — a part-day is
    reported as a full bucket by `az monitor metrics list` and would drag the
    averaged op rate down in proportion to how early in the day you run this."""
    now = datetime.fromtimestamp(now_epoch if now_epoch is not None else time.time(), timezone.utc)
    end = now.replace(hour=0, minute=0, second=0, microsecond=0)
    start = end - timedelta(days=days)
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    return start.strftime(fmt), end.strftime(fmt)


def parse_transactions(envelope: dict) -> dict[str, float]:
    """Sum an `az monitor metrics list --filter "ApiName eq '*'"` envelope into
    {ApiName: total ops}. Buckets with no `total` key are gaps, not zeroes, and are
    skipped so they cannot dilute an average."""
    out: dict[str, float] = {}
    for metric in envelope.get("value") or []:
        for ts in metric.get("timeseries") or []:
            api = None
            for md in ts.get("metadatavalues") or []:
                name = md.get("name")
                key = name.get("value") if isinstance(name, dict) else name
                if key == "apiname":
                    api = md.get("value")
            if api is None:
                continue
            for point in ts.get("data") or []:
                if point.get("total") is not None:
                    out[api] = out.get(api, 0.0) + float(point["total"])
    return out


def last_bucket(envelope: dict, api: str) -> float | None:
    """The most recent whole-day total for one ApiName. Compared against the window
    average this detects a RAMP — an account whose volume is still climbing reads
    low when averaged, so the report has to say the number is a trailing one."""
    best_ts, best_val = "", None
    for metric in envelope.get("value") or []:
        for ts in metric.get("timeseries") or []:
            names = []
            for md in ts.get("metadatavalues") or []:
                name = md.get("name")
                key = name.get("value") if isinstance(name, dict) else name
                if key == "apiname":
                    names.append(md.get("value"))
            if api not in names:
                continue
            for point in ts.get("data") or []:
                if point.get("total") is not None and point.get("timeStamp", "") >= best_ts:
                    best_ts, best_val = point["timeStamp"], float(point["total"])
    return best_val


def parse_scalar_total(envelope: dict) -> float:
    """Sum an undimensioned metric envelope (e.g. Ingress) to a single total."""
    total = 0.0
    for metric in envelope.get("value") or []:
        for ts in metric.get("timeseries") or []:
            for point in ts.get("data") or []:
                if point.get("total") is not None:
                    total += float(point["total"])
    return total


def calibrated_avg_append(ingress_bytes: float, append_ops: float) -> float | None:
    """Mean bytes per AppendBlock, measured. None when either side is absent —
    a calibration off zero observations is worse than the documented default."""
    if append_ops <= 0 or ingress_bytes <= 0:
        return None
    return ingress_bytes / append_ops


def fetch_metrics(resource_id: str, days: int) -> dict | None:
    """Read the billable op counts and ingress bytes off Azure Monitor.

    Returns per-day rates plus the calibrated mean append size, or None when the
    metrics are unreachable (needs `Monitoring Reader`) or the window is empty —
    callers fall back to the modelled estimate and must say so."""
    start, end = metric_window(days)
    base = ["monitor", "metrics", "list", "--resource", f"{resource_id}/blobServices/default",
            "--interval", "P1D", "--start-time", start, "--end-time", end,
            "--aggregation", "Total", "-o", "json"]
    tx = az([*base, "--metric", "Transactions", "--filter", "ApiName eq '*'"])
    if tx.returncode != 0:
        return None
    try:
        envelope = json.loads(tx.stdout or "{}")
    except json.JSONDecodeError:
        return None
    ops = parse_transactions(envelope)
    appends = ops.get("AppendBlock", 0.0)
    if appends <= 0:
        return None  # nothing streaming, or no visibility — don't pretend either way

    ingress = 0.0
    ing = az([*base, "--metric", "Ingress"])
    if ing.returncode == 0:
        try:
            ingress = parse_scalar_total(json.loads(ing.stdout or "{}"))
        except json.JSONDecodeError:
            ingress = 0.0

    def bucket(names: tuple[str, ...]) -> float:
        return sum(ops.get(n, 0.0) for n in names)

    latest = last_bucket(envelope, "AppendBlock")
    return {
        "append_ops_per_day": appends / days,
        "latest_day_appends": latest,
        "trend_ratio": (latest / (appends / days)) if (latest and appends) else None,
        "write_other_ops_per_day": bucket(WRITE_API_NAMES) / days,
        "list_ops_per_day": bucket(LIST_API_NAMES) / days,
        "read_ops_per_day": bucket(READ_API_NAMES) / days,
        "ingress_bytes_per_day": ingress / days,
        "avg_append": calibrated_avg_append(ingress, appends),
        "window": f"{start[:10]}..{end[:10]}",
        "days": days,
    }


def other_ops_cost(m: dict | None, p: dict) -> float:
    """£/month for the account-wide operations that aren't AppendBlock. Listing is
    billed at the WRITE rate (meter: "LRS List and Create Container Operations"),
    which is why excluding it as "small" understated the bill by ~10%."""
    if not m:
        return 0.0
    per_mo = lambda n: n * DAYS_PER_MONTH / 10_000
    writes = per_mo(m.get("list_ops_per_day", 0.0) + m.get("write_other_ops_per_day", 0.0))
    reads = per_mo(m.get("read_ops_per_day", 0.0))
    return writes * p["write_10k"] + reads * p["read_10k"]


def append_rate_per_day(nbytes: int, p: dict) -> float:
    """The container's AppendBlock rate (ops/day) — the thing that drives the bill.

    MEASURED path (default): the account-wide count came off Azure Monitor, so all
    this does is allocate it by resident-byte share. Approximate per container,
    exact in total — see ACCURACY in the module docstring.

    FALLBACK path: back-solve from resident bytes. At steady state resident bytes
    are the append rate times avg_append_bytes times the ACTUAL retention window,
    so rate = bytes / (avg_append * actual_retention). Only as good as avg_append,
    which is exactly how #228 happened."""
    m = p.get("measured")
    if m:
        total = p.get("total_bytes") or 0
        return m["append_ops_per_day"] * (nbytes / total) if total else 0.0
    avg, aret = p["avg_append"], p["actual_retention"]
    return nbytes / (avg * aret) if (avg and aret) else 0.0


def effective_scale(short_name: str, p: dict) -> float:
    """Per-container activity multiplier: the global --volume-scale times any
    --scale NAME=FACTOR whose NAME is a substring of the (insights-logs-stripped)
    container name. Models 'what if this stream were busier/quieter' — e.g. halving
    graph2otel's own poll frequency roughly halves the graphactivity container."""
    s = p["volume_scale"]
    for pat, f in p["per_container"].items():
        if pat in short_name:
            s *= f
    return s


def cost_row(nbytes: int, scale: float, p: dict) -> tuple[float, float, float, float]:
    """Estimated (storage, write, total) £/month for one container under the
    current scenario, plus its modeled resident bytes.

    Forward model: measured bytes -> append rate (via ACTUAL retention) -> apply
    the activity `scale` -> price the writes at that rate over a month, and price
    storage against the bytes that rate leaves resident under the MODELED
    retention. With scale=1 and model_retention==actual_retention it reproduces
    the measured bytes exactly. Reads/listing are excluded (small, not implied by
    size). Assumes steady state — a container still backfilling reads high."""
    rate = append_rate_per_day(nbytes, p) * scale
    write = (rate * DAYS_PER_MONTH / 10_000) * p["write_10k"]
    modeled_bytes = rate * p["avg_append"] * p["model_retention"]
    storage = (modeled_bytes / GIB) * p["storage"]
    return storage, write, storage + write, modeled_bytes


def gbp(n: float) -> str:
    return f"£{n:,.2f}" if abs(n) >= 0.005 else f"£{n:.3f}"


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


def human_count(n: float) -> str:
    """Compact op-count formatter: 683000 -> '683.0K', 1_200_000 -> '1.2M'."""
    n = float(n)
    for unit in ("", "K", "M", "B"):
        if abs(n) < 1000:
            return f"{n:,.0f}{unit}" if unit == "" else f"{n:,.1f}{unit}"
        n /= 1000
    return f"{n:,.1f}T"


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
                    oldest: dict | None, auth_label: str, top: int | None,
                    p: dict, retention_detected: bool) -> None:
    total = sum(r["bytes"] for r in rows)
    total_blobs = sum(r["blobs"] for r in rows)
    shown = rows[:top] if top else rows
    biggest = max((r["bytes"] for r in rows), default=1) or 1
    barw = 12
    tot_store = tot_write = tot_appends = 0.0

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

    hdr = (f"  {'CONTAINER':<30}{'SIZE':>10} {'STORE £':>8} {'WRITE £':>8} {'WR/MO':>7} "
           f"{'%':>5}  {'BAR':<{barw}} {'AGE':>6} {'Δ/DAY':>10}")
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
        scale = effective_scale(name, p)
        store, write, _, _ = cost_row(r["bytes"], scale, p)
        appends_mo = append_rate_per_day(r["bytes"], p) * scale * DAYS_PER_MONTH
        big = r["bytes"] >= 20 * 1024**2
        name_c = (YELLOW if big else CYAN)(f"{name:<30.30}")
        print(f"  {name_c}{human(r['bytes']):>10} {gbp(store):>8} {gbp(write):>8} "
              f"{human_count(appends_mo):>7} {pct:>4.1f}%  {bar:<{barw}} "
              f"{age(r['newest']):>6} {rate_c:>10}")
    baseline = 0.0  # measured total (scale=1, model_retention==actual): the "today" number
    for r in rows:  # cost totals over ALL containers, not just the shown top-N
        scale = effective_scale(r["name"].replace("insights-logs-", ""), p)
        s, w, _, _ = cost_row(r["bytes"], scale, p)
        tot_store += s
        tot_write += w
        tot_appends += append_rate_per_day(r["bytes"], p) * scale * DAYS_PER_MONTH
        bs, bw, _, _ = cost_row(r["bytes"], 1.0, {**p, "model_retention": p["actual_retention"]})
        baseline += bs + bw
    if top and len(rows) > top:
        rest = sum(r["bytes"] for r in rows[top:])
        print(DIM(f"  … {len(rows)-top} more containers, {human(rest)}"))
    print(DIM("  " + "-" * (len(hdr) - 2)))
    total_label = f"{'TOTAL':<30}"
    print("  " + BOLD(total_label) + BOLD(f"{human(total):>10}")
          + BOLD(f" {gbp(tot_store):>8}") + BOLD(f" {gbp(tot_write):>8}")
          + BOLD(f" {human_count(tot_appends):>7}"))
    ret_src = "detected" if retention_detected else "assumed"
    scenario = (p["model_retention"] != p["actual_retention"] or p["volume_scale"] != 1.0 or p["per_container"])
    m = p.get("measured")
    # Non-append ops are account-wide (no container dimension), so they sit outside
    # the per-row totals but very much inside the bill — listing alone is ~10% of it.
    other = other_ops_cost(m, p) * (p["volume_scale"] if scenario else 1.0)
    baseline += other_ops_cost(m, p)
    total_cost = tot_store + tot_write + other
    print()
    label = "modeled monthly cost" if scenario else "est. monthly cost"
    print(DIM(f"  {label} ≈ ") + BOLD(gbp(total_cost)) +
          DIM(f"  (storage {gbp(tot_store)} + write-ops {gbp(tot_write)} ≈ "
              f"{human_count(tot_appends)} appends/mo + other ops {gbp(other)})"))
    if scenario:
        delta = total_cost - baseline
        arrow = (GREEN if delta <= 0 else RED)(f"{'+' if delta > 0 else ''}{gbp(delta)}")
        print(DIM(f"  vs measured today {gbp(baseline)} → ") + arrow)
        knobs = [f"model-retention {p['model_retention']:g}d"]
        if p["volume_scale"] != 1.0:
            knobs.append(f"volume ×{p['volume_scale']:g}")
        for k, v in p["per_container"].items():
            knobs.append(f"{k} ×{v:g}")
        print(DIM("  scenario: " + " · ".join(knobs)))
    print()
    if m:
        print(GREEN("  MEASURED") + DIM(
            f" — op counts read from Azure Monitor over {m['window']} ({m['days']}d): "
            f"{human_count(m['append_ops_per_day'])} appends/day, "
            f"{human_count(m['list_ops_per_day'])} lists/day, "
            f"{human_count(m['read_ops_per_day'])} reads/day, "
            f"{human(m['ingress_bytes_per_day'])}/day ingress."))
        print(DIM(f"  mean append size calibrated live at {p['avg_append']:,.0f} B "
                  f"(default {AVG_APPEND_BYTES:,} B is Entra-only and unreliable here)."))
        ratio = m.get("trend_ratio")
        if m["days"] > 1 and ratio and (ratio >= 1.25 or ratio <= 0.8):
            direction = "RAMPING UP" if ratio > 1 else "FALLING"
            print(YELLOW(f"  {direction}") + DIM(
                f" — the last full day ran at {human_count(m['latest_day_appends'])} appends "
                f"({ratio:.2f}x the {m['days']}-day average), so this total is a TRAILING figure. "
                f"Rerun with --metrics-days 1 for the current run-rate."))
        print(DIM("  per-container £ are the account-wide op count allocated by BYTE SHARE — the "
                  "Transactions"))
        print(DIM("  metric has no container dimension, so rows under-state small-record streams "
                  "(Entra) and"))
        print(DIM("  over-state large-batch ones (Defender). Account totals are exact; row splits "
                  "are indicative."))
    else:
        print(RED("  MODELLED — no Azure Monitor data") + DIM(
            f"; appends inferred from resident bytes ÷ ({p['avg_append']:,} B × "
            f"{p['actual_retention']:g}d)."))
        print(DIM("  This path is only as good as --avg-append-bytes and has been 4.9x wrong "
                  "before (#228)."))
        print(DIM("  Grant 'Monitoring Reader' on the account, or drop --no-metrics, for real "
                  "numbers."))
    print(DIM(f"  anchor: Hot LRS uksouth · storage £{p['storage']}/GiB-mo · "
              f"write £{p['write_10k']}/10k · read £{p['read_10k']}/10k · "
              f"{p['avg_append']:,.0f}B/append · retention {p['actual_retention']:g}d ({ret_src})"))
    print(DIM("  write-ops dominate the bill and scale with fleet/collector activity, not resident size.\n"))


def render_html(path: str, account: str, rows: list[dict], prev: dict | None,
                oldest: dict | None, p: dict) -> None:
    total = sum(r["bytes"] for r in rows) or 1
    biggest = max((r["bytes"] for r in rows), default=1) or 1
    tot_store = tot_write = tot_appends = 0.0
    trs = []
    for r in rows:
        pct = 100 * r["bytes"] / total
        w = 100 * r["bytes"] / biggest
        rate = per_day(r["bytes"], oldest, r["name"])
        rate_s = "—" if rate is None else human_signed(rate)
        name = r["name"].replace("insights-logs-", "")
        scale = effective_scale(name, p)
        store, write, _, _ = cost_row(r["bytes"], scale, p)
        appends_mo = append_rate_per_day(r["bytes"], p) * scale * DAYS_PER_MONTH
        tot_store += store
        tot_write += write
        tot_appends += appends_mo
        big = r["bytes"] >= 20 * 1024**2
        trs.append(
            f"<tr><td class='n'>{name}{' <span class=hi>HV</span>' if big else ''}</td>"
            f"<td class='num'>{human(r['bytes'])}</td><td class='num'>{gbp(store)}</td>"
            f"<td class='num'>{gbp(write)}</td><td class='num'>{human_count(appends_mo)}</td>"
            f"<td class='num'>{pct:.1f}%</td>"
            f"<td class='bar'><span style='width:{w:.1f}%'></span></td>"
            f"<td class='num'>{r['blobs']:,}</td><td class='num'>{rate_s}</td></tr>")
    other = other_ops_cost(p.get("measured"), p)
    tot_cost = tot_store + tot_write + other
    since = ""
    if prev:
        d = sum(r["bytes"] for r in rows) - prev.get("totals", {}).get("bytes", 0)
        dt_h = (time.time() - prev.get("epoch", 0)) / 3600
        since = f"<p class='sub'>Since last snapshot ({dt_h:.1f}h ago): <b>{human_signed(d)}</b></p>"
    m = p.get("measured")
    provenance = (
        f"<b>Measured</b> — op counts from Azure Monitor over {m['window']} ({m['days']}d): "
        f"{human_count(m['append_ops_per_day'])} appends/day, {human_count(m['list_ops_per_day'])} "
        f"lists/day, {human(m['ingress_bytes_per_day'])}/day ingress; mean append size calibrated "
        f"at {p['avg_append']:,.0f}&nbsp;B. Per-container £ allocate the account-wide op count by "
        "byte share (the Transactions metric has no container dimension), so rows under-state "
        "small-record streams and over-state large-batch ones — account totals are exact, row "
        "splits indicative."
        if m else
        f"<b>Modelled, not measured</b> — no Azure Monitor data; appends inferred from resident "
        f"bytes &divide; ({p['avg_append']:,.0f}&nbsp;B &times; {p['actual_retention']:g}d). This "
        "path has been 4.9&times; wrong before (#228); grant 'Monitoring Reader' for real numbers."
    )
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
<table><thead><tr><th>Container</th><th class=num>Size</th><th class=num>Store £/mo</th>
<th class=num>Write £/mo</th><th class=num>Writes/mo</th><th class=num>%</th>
<th>Share</th><th class=num>Blobs</th><th class=num>Δ/day</th></tr></thead>
<tbody>{''.join(trs)}</tbody>
<tfoot><tr><td>TOTAL</td><td class=num>{human(total)}</td><td class=num>{gbp(tot_store)}</td>
<td class=num>{gbp(tot_write)}</td><td class=num>{human_count(tot_appends)}</td><td colspan=4></td></tr></tfoot></table>
<p class=sub>{'Modeled' if (p['model_retention'] != p['actual_retention'] or p['volume_scale'] != 1.0 or p['per_container']) else 'Est.'} monthly cost ≈ <b>{gbp(tot_cost)}</b> — appends {gbp(tot_write)} + storage {gbp(tot_store)} + other ops {gbp(other)} (Hot LRS uksouth, actual retention {p['actual_retention']:g}d, model retention {p['model_retention']:g}d, volume ×{p['volume_scale']:g}, write-ops dominated). HV = high-volume (&ge;20&nbsp;MB). Δ/day from the oldest snapshot.</p>
<p class=sub>{provenance}</p>
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
    ap.add_argument("--retention-days", type=float, metavar="D",
                    help="ACTUAL lifecycle delete age — the measurement anchor used to read each "
                         "container's append rate from its bytes (default: auto-detect, else "
                         f"{DEFAULT_RETENTION_DAYS}). Override only if auto-detect is wrong.")
    ap.add_argument("--model-retention-days", type=float, metavar="D",
                    help="WHAT-IF retention to price against (default: same as actual). Model a "
                         "different retention without changing the measured append rate — storage "
                         "scales with it, write-ops don't.")
    ap.add_argument("--volume-scale", type=float, default=1.0, metavar="X",
                    help="scale every container's activity by X (e.g. 2.0 = double the traffic/poll "
                         "frequency). Both write-ops and resident storage scale with it.")
    ap.add_argument("--scale", action="append", default=[], metavar="NAME=X",
                    help="scale one container's activity: NAME is a substring of the container name, "
                         "X the factor. Repeatable. E.g. --scale graphactivity=0.5 models halving "
                         "graph2otel's own poll frequency.")
    ap.add_argument("--metrics-days", type=int, default=DEFAULT_METRIC_DAYS, metavar="N",
                    help="whole UTC days of Azure Monitor history to average the measured op rate "
                         f"over (default {DEFAULT_METRIC_DAYS}; today is always excluded)")
    ap.add_argument("--no-metrics", action="store_true",
                    help="skip Azure Monitor and use the modelled bytes/avg_append estimate. Only "
                         "an order-of-magnitude check — it has been 4.9x wrong (#228).")
    ap.add_argument("--price-storage-gb-mo", type=float, default=PRICE_STORAGE_GB_MONTH, help="£/GiB-month storage price")
    ap.add_argument("--price-write-10k", type=float, default=PRICE_WRITE_PER_10K, help="£ per 10k write ops")
    ap.add_argument("--price-read-10k", type=float, default=PRICE_READ_PER_10K, help="£ per 10k read ops")
    ap.add_argument("--avg-append-bytes", type=int, default=None,
                    help="override the mean AppendBlock size in bytes (default: calibrated live "
                         f"from Ingress/AppendBlock, or {AVG_APPEND_BYTES} when metrics are off)")
    args = ap.parse_args()

    if args.metrics_days < 1:
        sys.exit("--metrics-days must be at least 1 (whole UTC days only).")

    require_az()
    flags, auth_label = auth_flags(args.account, args.use_key)
    names = list_containers(args.account, flags)
    if not names:
        sys.exit(f"No containers found in '{args.account}'.")

    rg, resource_id = account_ids(args.account)

    if args.retention_days is not None:
        actual_retention, retention_detected = args.retention_days, False
    else:
        detected = detect_retention_days(args.account, rg)
        actual_retention = detected if detected else DEFAULT_RETENTION_DAYS
        retention_detected = detected is not None

    measured = None
    if not args.no_metrics and resource_id:
        measured = fetch_metrics(resource_id, args.metrics_days)
    # Explicit --avg-append-bytes always wins; otherwise prefer the live calibration
    # and only fall back to the documented Entra-only constant.
    avg_append = args.avg_append_bytes
    if avg_append is None:
        avg_append = (measured or {}).get("avg_append") or AVG_APPEND_BYTES

    per_container = {}
    for spec in args.scale:
        if "=" not in spec:
            sys.exit(f"--scale expects NAME=FACTOR, got {spec!r}")
        k, v = spec.rsplit("=", 1)
        try:
            per_container[k] = float(v)
        except ValueError:
            sys.exit(f"--scale factor must be a number, got {v!r}")

    pricing = {
        "storage": args.price_storage_gb_mo,
        "write_10k": args.price_write_10k,
        "read_10k": args.price_read_10k,
        "avg_append": avg_append,
        "actual_retention": actual_retention,
        "model_retention": args.model_retention_days if args.model_retention_days is not None else actual_retention,
        "volume_scale": args.volume_scale,
        "per_container": per_container,
        "measured": measured,
        "total_bytes": 0,  # filled in once the containers are sized (byte-share allocation)
    }

    with ThreadPoolExecutor(max_workers=12) as ex:
        rows = list(ex.map(lambda n: size_container(args.account, flags, n), names))
    rows.sort(key=lambda r: r["bytes"], reverse=True)
    pricing["total_bytes"] = sum(r["bytes"] for r in rows)

    hist = load_history(args.history)
    prev = prev_for(hist, args.account)
    oldest = oldest_for(hist, args.account)

    snap = {
        "epoch": time.time(),
        "iso": datetime.now(timezone.utc).isoformat(),
        "account": args.account,
        "totals": {"bytes": sum(r["bytes"] for r in rows), "blobs": sum(r["blobs"] for r in rows)},
        "containers": {r["name"]: {"bytes": r["bytes"], "blobs": r["blobs"]} for r in rows},
        # Recorded so a history file can show how the op rate and the mean append size
        # moved, not just how the bytes did — the two diverge (#228).
        "metrics": measured,
        "avg_append_bytes": avg_append,
    }

    if args.json:
        print(json.dumps(snap, indent=2))
    else:
        render_terminal(args.account, rows, prev, oldest, auth_label, args.top,
                        pricing, retention_detected)
        errs = [r for r in rows if r.get("error")]
        if errs:
            print(RED(f"  {len(errs)} container(s) errored:"))
            for r in errs:
                print(RED(f"    {r['name']}: {r['error']}"))

    if args.html:
        render_html(args.html, args.account, rows, prev, oldest, pricing)
        if not args.json:
            print(DIM(f"  HTML report written to {args.html}\n"))

    if not args.no_record:
        record_snapshot(args.history, snap)


if __name__ == "__main__":
    main()
