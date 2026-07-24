"""OTLP -> Prometheus metric-name derivation, mirroring internal/signalcatalog.

# Why this exists twice

Every CATALOGUED metric already carries its derived ``prometheus_name``, so the
board modules never need this: they name the OTEL metric and the builder reads
the normalized form out of the catalog. This module exists for the one surface
the catalog structurally cannot see — the self-observability metrics emitted
outside any collector package (the scheduler, the HTTP transport, the
cardinality limiter), which no ``testdata/signals.json`` golden captures.

# Why a second implementation is safe here

``tests/test_build_dashboard.py`` asserts this function reproduces
``prometheus_name`` for all 274 cataloged metrics. So the two implementations
are pinned to each other by a test over real data on every run: they cannot
drift silently, and a change to the Go rule fails here immediately.
"""

from __future__ import annotations

import re

_TOKEN_SPLIT = re.compile(r"[^A-Za-z0-9:]+")

# Same table as internal/signalcatalog.unitSuffixes. A unit that is absent
# contributes NO suffix.
UNIT_SUFFIXES = {
    "d": "days", "h": "hours", "min": "minutes", "s": "seconds",
    "ms": "milliseconds", "us": "microseconds", "ns": "nanoseconds",
    "By": "bytes", "KiBy": "kibibytes", "MiBy": "mebibytes",
    "GiBy": "gibibytes", "TiBy": "tebibytes",
    "KBy": "kilobytes", "MBy": "megabytes", "GBy": "gigabytes", "TBy": "terabytes",
    "m": "meters", "V": "volts", "A": "amperes", "J": "joules", "W": "watts",
    "g": "grams", "Cel": "celsius", "Hz": "hertz", "%": "percent",
}


def strip_annotations(unit: str) -> str:
    """Remove UCUM annotations: '{device}' -> '', 's' -> 's'."""
    return re.sub(r"\{[^}]*\}", "", unit).strip()


def prom_name(name: str, unit: str, kind: str) -> str:
    """Derive the Prometheus name for an OTEL metric. See internal/signalcatalog."""
    tokens = [t for t in _TOKEN_SPLIT.split(name) if t]
    main = strip_annotations(unit)
    suffix = UNIT_SUFFIXES.get(main, "")
    if suffix and suffix not in tokens:
        tokens.append(suffix)
    if main == "1" and kind == "gauge" and "ratio" not in tokens:
        tokens.append("ratio")
    if kind == "sum":
        while tokens and tokens[-1] == "total":
            tokens.pop()
        tokens.append("total")
    return "_".join(tokens)
