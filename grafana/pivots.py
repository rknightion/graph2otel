"""Entity-centric investigation pivots (#305).

Pure standard library, like the rest of ``grafana/``.

# What this is for

An analyst holding one thing — a device id from an alert, a UPN from a sign-in
row, a network message id from a quarantine record — wants every *other* signal
graph2otel has recorded about that same entity, without hand-writing LogQL and
without losing the tenant or the time range they were looking at.

Six entity kinds are covered: device, application/service principal, account,
email message, security alert, security incident.

# What it is NOT

**A Loki link is navigation. It is not a join and it is not a correlation
verdict.** Two records naming the same id are two records naming the same id;
nothing here proves they describe the same real-world thing, and several of these
identifiers are *source-scoped* — ``device_id`` is Intune's managed-device id on
``intune.*`` and Defender's machine id on ``defender.*``, which are different
namespaces for the same physical machine, and graph2otel deliberately does not map
between them (the same reason it does not map ``/security/alerts_v2``'s own
``tenantId``). Every generated panel says so, because "which signals name this
device" reads like a correlation result and is not one.

# Why the pivots are declared, but their event sets are derived

A pivot's query has two halves, and they rot in opposite directions:

* **the event set** is *derived* — every cataloged log event that carries the
  identifier attribute. Declaring it would mean a new collector emitting
  ``device_id`` silently stayed outside the device pivot, which is the drift the
  coverage gate exists to prevent;
* **the anchors** are *declared* — a small set of ``(event, key)`` pairs the pivot
  promises to reach. Derivation alone cannot satisfy #305's second acceptance
  criterion: if the whole set is derived, an event losing the attribute simply
  drops out of it and the build stays green while the pivot quietly stops
  reaching that signal. An anchor is the thing that fails.

``also_named_by`` is the third half-truth made explicit: keys that name the same
entity and are deliberately **not** queried, because they carry a different value
shape (a directory object id is not a UPN) or sit on a single event. They are
listed in the panel description so the gap is visible rather than silent, and they
are gated too — a documented synonym the catalog no longer has makes that note a
lie.

# The empty-input trap

In LogQL an absent structured-metadata key compares equal to the empty string, so
``| device_id=`$pivot_device` `` with an unset variable matches every record that
has **no** device_id — the pivot would dump the whole estate instead of showing
nothing. Every target therefore also requires the key to be non-empty
(``| device_id=~`.+` ``), which makes an empty input match nothing by
construction. Both filters are typed, so both keys are validated against the
catalog like any other (#306).
"""

from __future__ import annotations

import re

import v2

# Where a pivot link lands. The landing tab, deliberately: it is the one tab that
# is never conditional, and a dtab into conditioned-away content renders a
# completely blank body with no message (measured, #399). The nested leaf-tab
# ``dtab`` form is not used, matching #307 — nothing here needs it, because the
# pivot rows are rows of one leaf rather than leaves of their own.
PIVOT_TAB = "Overview"

# ``from``/``to`` and ``${__all_variables}`` keep the tenant selection and the
# time range the analyst was already looking at. A pivot that resets either is
# wrong: it answers a different question from the one that was asked.
PIVOT_URL = (f"/d/graph2otel?dtab={v2.slug(PIVOT_TAB)}"
             "&from=${__from}&to=${__to}&${__all_variables}")

# Panel-title prefixes, so a gate can find the generated pivot panels in the
# shipped manifest without a second declaration to drift.
COUNT_PREFIX = "Which signals name this "
ROWS_PREFIX = "Every record naming this "
TITLE_PREFIXES = (COUNT_PREFIX, ROWS_PREFIX)

NOT_A_JOIN = (
    "This is navigation, **not a join** and not a correlation verdict: rows here "
    "are records that name the same identifier, which is not proof they describe "
    "the same real-world thing."
)

PREAMBLE = """\
### Investigate one entity across every signal

Paste an identifier into one of the inputs at the top of this dashboard — device,
application, account, email message, alert or incident — and expand the matching
row below. Each row lists which of graph2otel's log signals name that entity, and
then every record that names it, in the tenant and time range currently selected.

**Metrics cannot answer this and never will.** Per-entity identifiers are
deliberately not metric labels (#112): a series keyed by UPN or device grows with
tenant size and gets one sample ever. The log twin answers "which one" for free.

**These are navigation aids, not joins.** Two records naming the same id are two
records naming the same id. Some identifiers are also source-scoped — `device_id`
is Intune's managed-device id on `intune.*` and Defender's machine id on
`defender.*` — so a match proves a record names that id, never that two records
are the same device.

Rows are collapsed on purpose: expanding all six would run every entity's queries
for the five you are not investigating.
"""


class Entity:
    """One pivotable entity kind: what identifies it, and where that reaches."""

    __slots__ = ("kind", "title", "variable", "input_label", "meaning",
                 "direction", "keys", "anchors", "also_named_by", "caveat",
                 "linked_from")

    def __init__(self, kind: str, title: str, variable: str, input_label: str,
                 meaning: str, direction: str, keys: tuple, anchors: tuple,
                 also_named_by: tuple = (), caveat: str = "",
                 linked_from: tuple = ()):
        self.kind = kind
        self.title = title
        self.variable = variable
        self.input_label = input_label
        self.meaning = meaning
        self.direction = direction
        self.keys = keys
        self.anchors = anchors
        self.also_named_by = also_named_by
        self.caveat = caveat
        # Entity kinds whose own pivot panels carry a link to this one. An
        # identifier an analyst never *holds* — only reads off another record —
        # is unreachable from a domain log panel, and a pivot nobody can reach is
        # a surface nobody finds. The link is still signal-agreement checked
        # against the linking panel's real queries, so this declaration cannot
        # invent a route the data does not support.
        self.linked_from = linked_from

    def row_title(self) -> str:
        article = "an" if self.title[:1].lower() in "aeiou" else "a"
        return f"Investigate {article} {self.title}"

    def link_title(self) -> str:
        """The panel-link text.

        States the identifier's meaning *and* the direction, because "device" on
        its own does not tell an analyst what the link claims before they click
        it (#305's fourth acceptance criterion).
        """
        return f"Investigate this {self.title} — {self.direction}"

    def description(self, cat, panel: str) -> str:
        """The panel description: what the identifier means, and what it reaches."""
        reach = ", ".join(
            f"`{key}` ({len(events_for(cat, key))} log events)"
            for key in self.keys
        )
        parts = [
            f"**{panel}** {self.direction.capitalize()}.",
            f"**Identifier:** {self.meaning}",
            f"**Queried keys:** {reach}. An input matching any one of them "
            "matches; an empty input matches nothing.",
        ]
        if self.also_named_by:
            parts.append(
                "**Deliberately not queried:** "
                + ", ".join(f"`{key}`" for key in self.also_named_by)
                + ". They name the same entity in a different value shape or a "
                "narrower namespace, and folding them into one input would make "
                "an empty result ambiguous — query them directly when you hold "
                "one."
            )
        if self.caveat:
            parts.append(f"**Read this first:** {self.caveat}")
        parts.append(NOT_A_JOIN)
        return "\n\n".join(parts)

    def __repr__(self) -> str:  # pragma: no cover - diagnostics only
        return f"Entity({self.kind!r})"


ENTITIES = [
    Entity(
        kind="device",
        title="device",
        variable="pivot_device",
        input_label="Device (id or name)",
        meaning=(
            "the device the record is ABOUT — the managed or onboarded device the "
            "source system names, never the device that observed the event."
        ),
        direction=(
            "this device's compliance, configuration, certificate, encryption, "
            "startup, logon and vulnerability records"
        ),
        keys=("device_id", "device_name"),
        anchors=(
            ("intune.device_hardware", "device_id"),
            ("intune.compliance_alert", "device_id"),
            ("defender.device_logon", "device_id"),
            ("defender.vulnerability", "device_id"),
            ("intune.managed_device", "device_name"),
            ("defender.device_info", "device_name"),
        ),
        also_named_by=("aad_device_id", "serial_number", "device_serial_number"),
        caveat=(
            "`device_id` is source-scoped. On `intune.*` it is Intune's "
            "managed-device id; on `defender.*` it is Defender's machine id. They "
            "are different id namespaces for the same physical machine and "
            "graph2otel does not map between them, so pivoting on an Intune id "
            "will not reach Defender rows. `device_name` is usually what bridges "
            "the two, and is usually what an alert quotes."
        ),
    ),
    Entity(
        kind="application",
        title="application or service principal",
        variable="pivot_app",
        input_label="Application (app id, SP object id)",
        meaning=(
            "the application the record is about. `app_id` is the Entra "
            "application (client) id, `service_principal_id` the directory object "
            "id of its service principal, and `application_id` the same app as "
            "other products name it. One app registration has all three and they "
            "are different values."
        ),
        direction=(
            "this app's sign-ins, credential and federated-credential state, "
            "consent and permission grants, risk detections and Graph activity"
        ),
        keys=("app_id", "service_principal_id", "application_id"),
        anchors=(
            ("entra.signin", "app_id"),
            ("entra.service_principal", "app_id"),
            ("entra.app_credential", "app_id"),
            ("entra.provisioning", "service_principal_id"),
            ("defender.oauth_app", "service_principal_id"),
            ("defender.cloud_app_event", "application_id"),
        ),
        also_named_by=("app_display_name", "app_object_id", "oauth_app_id"),
    ),
    Entity(
        kind="account",
        title="account",
        variable="pivot_account",
        input_label="Account (UPN)",
        meaning=(
            "the account named on the record, as a user principal name. Three "
            "attribute names carry the same UPN value — Entra writes "
            "`user_principal_name`, Intune writes `upn`, Defender writes "
            "`account_upn` — so all three are queried and one input covers them."
        ),
        direction=(
            "this account's sign-ins, risk detections, registration state, "
            "privilege elevations, certificates and mailbox records"
        ),
        keys=("user_principal_name", "upn", "account_upn"),
        anchors=(
            ("entra.signin", "user_principal_name"),
            ("entra.risk_detection", "user_principal_name"),
            ("m365.exchange_mailbox", "user_principal_name"),
            ("intune.epm_elevation_events", "upn"),
            ("intune.noncompliant_setting", "upn"),
            ("defender.identity_logon", "account_upn"),
            ("defender.behavior", "account_upn"),
        ),
        also_named_by=("user_id", "account_object_id", "account_name",
                       "user_display_name"),
        caveat=(
            "Object-id keys are a different value shape from a UPN, so they are "
            "not folded into this input: pasting a UPN into an object-id filter "
            "would match nothing and the empty result would look like a verdict."
        ),
    ),
    Entity(
        kind="message",
        title="email message",
        variable="pivot_message",
        input_label="Email message (network or internet message id)",
        meaning=(
            "the message the record is about. `network_message_id` is Microsoft's "
            "per-tenant id used across the Defender for Office 365 tables; "
            "`internet_message_id` is the RFC 5322 Message-ID from the header — "
            "the one an end user or an external system can quote."
        ),
        direction=(
            "this message's delivery verdict, attachments, URLs and clicks, "
            "quarantine state and transport trace"
        ),
        keys=("network_message_id", "internet_message_id"),
        anchors=(
            ("defender.email", "network_message_id"),
            ("defender.email_attachment", "network_message_id"),
            ("defender.quarantine", "network_message_id"),
            ("m365.audit", "network_message_id"),
            ("m365.message_trace", "internet_message_id"),
            ("defender.email_post_delivery", "internet_message_id"),
        ),
        also_named_by=("message_trace_id", "email_cluster_id", "message_id"),
    ),
    Entity(
        kind="alert",
        title="security alert",
        variable="pivot_alert",
        input_label="Security alert id",
        meaning=(
            "the alert the record is about. `alert_id` is the source product's own "
            "alert id — Defender XDR's on the advanced-hunting alert tables, PIM's "
            "on its own alerts, which are different namespaces — and "
            "`provider_alert_id` is the originating provider's id carried on the "
            "Graph security alert."
        ),
        direction=(
            "this alert's evidence rows and the Graph security-alert record that "
            "reports it"
        ),
        keys=("alert_id", "provider_alert_id"),
        anchors=(
            ("defender.alert_info", "alert_id"),
            ("defender.alert_evidence", "alert_id"),
            ("entra.pim_alert", "alert_id"),
            ("entra.security_alert", "provider_alert_id"),
        ),
    ),
    Entity(
        kind="incident",
        title="security incident",
        variable="pivot_incident",
        input_label="Security incident id",
        meaning=(
            "the incident that groups one or more alerts, as Microsoft's Graph "
            "security API reports it on each alert it contains."
        ),
        direction="every alert graph2otel has recorded under this incident",
        keys=("incident_id",),
        anchors=(
            ("entra.security_alert", "incident_id"),
        ),
        caveat=(
            "Exactly one cataloged log signal carries `incident_id` today "
            "(`entra.security_alert`), so this pivot lists the alerts in the "
            "incident and nothing else. Pivot from each alert id for its evidence."
        ),
        # Nobody holds an incident id to begin with: it is read off a Graph
        # security-alert record. So the route in is the alert pivot's own panels,
        # which query that record.
        linked_from=("alert",),
    ),
]


def events_for(cat, key: str) -> list:
    """Every cataloged log event that carries ``key``, in name order.

    Derived rather than declared so a new collector emitting the identifier joins
    the pivot with no human step — the same reason the metric coverage gate reads
    expressions instead of trusting a list.
    """
    return sorted(log.event for log in cat.logs.values() if key in log.keys)


def keyed_events(cat, entity: Entity) -> list:
    """``[(key, [event, ...]), ...]`` for one entity — one query target per key."""
    return [(key, events_for(cat, key)) for key in entity.keys
            if events_for(cat, key)]


def violations(cat) -> list:
    """Every way the declared pivots and the catalog disagree.

    Returned rather than raised so one build reports all of them.
    """
    found = []
    for entity in ENTITIES:
        for key in entity.keys:
            if not events_for(cat, key):
                found.append(
                    f"pivot {entity.kind!r}: identifier key {key!r} is carried by "
                    "no cataloged log event, so the pivot would match zero rows "
                    "silently. Either the attribute was renamed or the collectors "
                    "that emitted it are gone — fix the key or drop it"
                )
        for event, key in entity.anchors:
            if event not in cat.logs:
                found.append(
                    f"pivot {entity.kind!r}: anchor event {event!r} is not a "
                    "cataloged log event; the pivot no longer reaches the signal "
                    "it promises"
                )
                continue
            if key not in cat.log(event).keys:
                found.append(
                    f"pivot {entity.kind!r}: anchor event {event!r} no longer "
                    f"carries {key!r}, so it has silently dropped out of the "
                    "pivot's derived event set while the build stayed green"
                )
            if key not in entity.keys:
                found.append(
                    f"pivot {entity.kind!r}: anchor {event!r} names {key!r}, "
                    "which is not one of the pivot's queried keys"
                )
        for key in entity.also_named_by:
            if key in entity.keys:
                found.append(
                    f"pivot {entity.kind!r}: {key!r} is documented as deliberately "
                    "not queried but is in the queried keys"
                )
            elif not events_for(cat, key):
                found.append(
                    f"pivot {entity.kind!r}: {key!r} is documented to the operator "
                    "as an identifier this pivot does NOT cover, but no cataloged "
                    "event carries it — the note now describes nothing"
                )
        for kind in entity.linked_from:
            if kind not in {other.kind for other in ENTITIES}:
                found.append(
                    f"pivot {entity.kind!r} declares it is linked from "
                    f"{kind!r}, which is not a pivot kind, so nothing generates "
                    "that link and the pivot is unreachable"
                )
    kinds = [entity.kind for entity in ENTITIES]
    for kind in sorted({k for k in kinds if kinds.count(k) > 1}):
        found.append(f"pivot kind {kind!r} is declared more than once")
    return found


EVENT_FILTER_RE = re.compile(r"\| event_name=~?`\^?\(?([^`]*?)\)?\$?`")


def _events_in(expr: str) -> set:
    """Every event name a generated LogQL expression filters on."""
    found = set()
    for match in EVENT_FILTER_RE.finditer(expr):
        for part in match.group(1).split("|"):
            found.add(part.replace("\\", ""))
    return found


def _element_exprs(element: dict) -> list:
    queries = element["spec"]["data"]["spec"]["queries"]
    return [q["spec"]["query"]["spec"].get("expr", "") for q in queries]


def link_violations(cat, man: dict) -> list:
    """Every pivot link on the shipped manifest that is not about what it claims.

    Two properties, and the second is the one a numeric target cannot check: a
    link resolves and is still wrong. #307 hit this from the other side — panel
    ids shift and then point somewhere plausible instead of somewhere right — so
    the check here is *signal agreement*: the panel's own query must name an event
    that really carries one of the entity's identifier keys.
    """
    found = []
    by_title = {entity.link_title(): entity for entity in ENTITIES}
    slugs = {v2.slug(tab["spec"]["title"])
             for tab in man["spec"]["layout"]["spec"]["tabs"]}
    reached = set()
    for name, element in sorted(man["spec"]["elements"].items()):
        for link in element["spec"].get("links") or []:
            entity = by_title.get(link.get("title"))
            if entity is None:
                continue
            reached.add(entity.kind)
            dtab = re.search(r"[?&]dtab=([^&]+)", link.get("url", ""))
            if dtab is None or dtab.group(1) not in slugs:
                found.append(
                    f"{name}: pivot link to {entity.kind!r} names dtab "
                    f"{dtab.group(1) if dtab else None!r}, which is not a tab in "
                    "this dashboard. A wrong dtab slug is ignored SILENTLY and "
                    f"falls back to the first tab. Known: {sorted(slugs)}"
                )
            events = set()
            for expr in _element_exprs(element):
                events |= _events_in(expr)
            carried = {event for event in events
                       if event in cat.logs
                       and set(entity.keys) & set(cat.log(event).keys)}
            if not carried:
                found.append(
                    f"{name}: pivot link claims {entity.kind!r} but none of the "
                    f"events this panel queries ({sorted(events) or 'none'}) "
                    f"carries any of {list(entity.keys)}. A navigation aid that "
                    "points somewhere plausible instead of somewhere right is "
                    "worse than no link"
                )
    for entity in ENTITIES:
        if entity.kind not in reached:
            found.append(
                f"pivot {entity.kind!r} is reachable from no panel link, so "
                "nothing in the estate leads an analyst to it"
            )
    return found


def rows(b) -> list:
    """Build the pivot panels and return one ``RowsLayoutRow`` per entity.

    Collapsed by default: six expanded rows would run every entity's queries for
    the five entities the analyst is not investigating.
    """
    out = []
    for entity in ENTITIES:
        b.text_variable(entity.variable, entity.input_label,
                        description=entity.meaning)
        pairs = keyed_events(b.cat, entity)
        counts = b.pivot_table(
            pairs, entity.variable,
            title=f"{COUNT_PREFIX}{entity.title}",
            desc=entity.description(b.cat, "Which of graph2otel's log signals "
                                           "name it, and how often."),
            no_value=_no_value(entity),
            # One series per (tenant, event), and the device pivot alone spans 41
            # events: the default top-20 would truncate the tail of the answer to
            # "which signals name this" without saying so.
            topk=80,
            w=8, h=10,
        )
        records = b.pivot_logs(
            pairs, entity.variable,
            title=f"{ROWS_PREFIX}{entity.title}",
            desc=entity.description(b.cat, "Every record that names it, newest "
                                           "first."),
            no_value=_no_value(entity),
            w=16, h=10,
        )
        onward = [
            {"title": other.link_title(), "url": PIVOT_URL, "targetBlank": False}
            for other in ENTITIES if entity.kind in other.linked_from
        ]
        if onward:
            counts["links"] = list(onward)
            records["links"] = list(onward)
        out.append(v2.rowspec(entity.row_title(),
                              [{"w": 8, "h": 10, "spec": counts},
                               {"w": 16, "h": 10, "spec": records}],
                              collapse=True))
    return out


def _no_value(entity: Entity) -> str:
    return (
        f"No rows. Paste a value into the “{entity.input_label}” input at the top "
        "of this dashboard, then check the tenant and the time range. An empty "
        "input matches nothing on purpose — an unset identifier filter would "
        "otherwise match every record that has no such attribute."
    )
