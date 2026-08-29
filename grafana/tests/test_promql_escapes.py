"""Every generated Prometheus target must be parseable PromQL.

A regex written into a double-quoted PromQL string literal has its
backslashes consumed by the string layer, so ``collector=~"entra\\..+"``
reaches the parser as ``entra\\..+`` and fails with
``unknown escape sequence U+002E '.'``. The LogQL side of this dashboard
already avoids that by quoting regexes with backticks; these tests hold
the Prometheus side to the same rule.
"""

import json
import pathlib
import re
import unittest

DASHBOARD = pathlib.Path(__file__).resolve().parents[2] / "dashboards" / "graph2otel.json"

# PromQL double-quoted strings accept the Go escape set. A backslash before
# anything else is a parse error, and a regex metacharacter escape is the way
# this goes wrong in practice.
_VALID_ESCAPES = set('abfnrtv\\\'"`0123456789xuU')

_DOUBLE_QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')


def _exprs(node):
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "expr" and isinstance(value, str):
                yield value
            yield from _exprs(value)
    elif isinstance(node, list):
        for item in node:
            yield from _exprs(item)


def _bad_escapes(expr):
    for literal in _DOUBLE_QUOTED.findall(expr):
        for match in re.finditer(r"\\(.)", literal):
            if match.group(1) not in _VALID_ESCAPES:
                yield literal, match.group(1)


class PromQLEscapeTest(unittest.TestCase):
    def test_no_invalid_escape_in_double_quoted_string(self):
        dashboard = json.loads(DASHBOARD.read_text())
        offenders = []
        for expr in _exprs(dashboard):
            for literal, char in _bad_escapes(expr):
                offenders.append((literal, char, expr))
        self.assertEqual(
            [],
            offenders,
            "\n".join(
                f"invalid escape \\{char} in {literal!r} within {expr[:120]!r}"
                for literal, char, expr in offenders
            ),
        )


if __name__ == "__main__":
    unittest.main()
