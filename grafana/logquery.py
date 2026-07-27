"""Typed LogQL filters and group keys, validated against the signal catalog (#306).

Pure standard library, like the rest of ``grafana/``.

# What this fixes

Log filters and group keys used to be raw strings. A misspelled attribute was not
an error — LogQL has no schema, so ``| status_erorr_code!=`0` `` is a perfectly
valid pipeline stage that matches **nothing, silently, forever**. The generator's
own docstring claimed "a typo is a KeyError at build time"; that was true of
metric names and event names and **not** of the attributes inside a log query,
which is the exact class of bug #90, #143, #158 and #160 were all instances of.

So a filter is now a typed :class:`Filter` whose key is checked against the
event's real attribute set, and a ``by`` group key is checked the same way.

# Why there is still an escape hatch

A typed-only model would be a straitjacket: regex alternation chains,
``line_format``, ``unwrap`` and friends are legitimate LogQL that no small type
model covers. Blocking them would push authors back to hand-built strings
somewhere else.

So :class:`Raw` exists — but it is deliberately expensive to use. It must
**declare the attribute keys it references** and **state a reason**, and the
declared keys are validated exactly as a typed filter's key would be. That keeps
the escape honest: the gate still knows every attribute the query depends on, and
a reader can see why the typed form was not enough.

The rejected alternative was a raw string plus an extractor that infers the keys.
That extractor becomes a partial LogQL parser, and a partial parser either misses
constructs (silently validating nothing, the #139/#100 failure) or rejects valid
ones. Declaring the keys moves that work to the author, once, where the answer is
actually known.

# The framework overlay

``tenant_id`` and ``ingest_transport`` are stamped at the emitter boundary
(``telemetry.WithTenant`` / ``WithTransport``), not by collectors, so they are on
every record but are not always in a per-event catalog row. They are therefore
overlaid onto every event's permitted key set here rather than being special-cased
at call sites.

# What this does NOT change

The stream selector is still only ever ``{service_name="graph2otel"}``, built by
``Builder._selector()``. Attribute matching is a filter stage and never a stream
label. This module makes that rule easier to keep, never weaker: a
:class:`Filter` cannot express a stream selector at all.
"""

from __future__ import annotations

# Operator name -> LogQL label-filter operator. Named rather than spelled at call
# sites so a board module cannot invent `==` or `!~~` and have it sail through as
# an opaque string.
OPERATORS = {
    "eq": "=",
    "ne": "!=",
    "re": "=~",
    "nre": "!~",
}

# Stamped at the emitter boundary on every record (#143 tenant_id, #141
# ingest_transport, and the OTEL LogRecord EventName every emitted record
# carries), so they are queryable on every event whether or not the event's own
# catalog row lists them.
#
# ``event_name`` joined the overlay on #305. It was always guaranteed — every
# query this package builds emits ``| event_name=…`` unconditionally — but
# omitting it from the overlay meant the one grouping that makes a cross-event
# query readable, ``by=["event_name"]``, was reported as an attribute the event
# does not carry. That is the overlay's exact purpose: an attribute the framework
# stamps rather than the collector. It is not a general escape from catalog
# validation, and the three members are the whole list.
FRAMEWORK_KEYS = frozenset({"tenant_id", "ingest_transport", "event_name"})


class Filter:
    """One typed label filter: ``| key<op>`value` ``."""

    __slots__ = ("key", "op", "value")

    def __init__(self, key: str, op: str, value: str):
        if op not in OPERATORS:
            raise ValueError(
                f"unknown filter operator {op!r}; use one of {sorted(OPERATORS)}"
            )
        if not key:
            raise ValueError("a filter needs an attribute key")
        self.key = key
        self.op = op
        self.value = value

    def render(self) -> str:
        return f"{self.key}{OPERATORS[self.op]}`{self.value}`"

    def keys(self) -> set:
        return {self.key}

    def __repr__(self) -> str:  # pragma: no cover - diagnostics only
        return f"Filter({self.key!r}, {self.op!r}, {self.value!r})"


class Raw:
    """A hand-written LogQL fragment that declares what it touches, and why.

    ``text`` is inserted after a ``|`` exactly as given. ``keys`` must name every
    attribute the fragment references, and ``reason`` must say why the typed form
    could not express it — an escape hatch with no stated reason is just an
    unvalidated string with extra steps.
    """

    __slots__ = ("text", "_keys", "reason")

    def __init__(self, text: str, *, keys, reason: str):
        if not text.strip():
            raise ValueError("a raw filter needs text")
        declared = list(keys or [])
        if not declared:
            raise ValueError(
                f"raw filter {text!r} must declare the attribute keys it "
                "references, or the catalog gate validates nothing"
            )
        if not reason.strip():
            raise ValueError(
                f"raw filter {text!r} must state why the typed filter model "
                "cannot express it"
            )
        self.text = text.strip()
        self._keys = declared
        self.reason = reason.strip()

    def render(self) -> str:
        return self.text

    def keys(self) -> set:
        return set(self._keys)

    def __repr__(self) -> str:  # pragma: no cover - diagnostics only
        return f"Raw({self.text!r}, keys={sorted(self._keys)!r})"


def f(key: str, op: str, value: str) -> Filter:
    """Shorthand for :class:`Filter`, for readable board-module declarations."""
    return Filter(key, op, value)


def permitted_keys(cat, event: str) -> set:
    """Every attribute a query on ``event`` may reference."""
    return set(cat.log(event).keys) | set(FRAMEWORK_KEYS)


def render_filters(filters) -> list:
    """Render typed filters to LogQL fragments, rejecting bare strings.

    A bare string is refused rather than passed through: accepting one would
    reinstate exactly the unvalidated path this module exists to remove, and it
    would do so invisibly.
    """
    out = []
    for item in filters or []:
        if isinstance(item, str):
            raise TypeError(
                f"raw string filter {item!r} is not accepted; use "
                "logquery.f(key, op, value), or logquery.Raw(text, keys=[...], "
                "reason=...) when the typed model cannot express it"
            )
        out.append(item.render())
    return out


def violations(cat, event: str, filters=None, by=None) -> list:
    """Every filter or group key that names an attribute the event does not carry.

    Returned rather than raised so one build reports all of them, and so the
    caller can attribute them to a panel.
    """
    found = []
    try:
        permitted = permitted_keys(cat, event)
    except KeyError:
        # The event name itself is already validated by cat.log() at the call
        # site; nothing further is checkable here.
        return [f"{event!r} is not a cataloged log event"]

    for item in filters or []:
        for key in sorted(item.keys()):
            if key not in permitted:
                kind = "raw filter" if isinstance(item, Raw) else "filter"
                found.append(
                    f"{event}: {kind} references {key!r}, which the event does "
                    "not carry; the query would match zero rows silently"
                )
    for key in by or []:
        if key not in permitted:
            found.append(
                f"{event}: group key {key!r} is not an attribute of the event; "
                "the aggregation would collapse to a single empty series"
            )
    return found
