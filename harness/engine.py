"""Compile a Sigma file to one SQLite query with pySigma, then evaluate events against it.

Fail-closed: any modifier, value type or correlation type outside the allowlist
raises Unsupported, so a rule feature this harness has not self-tested is never
evaluated with guessed semantics. The backend owns condition semantics; this
module never evaluates a condition itself.
"""

from __future__ import annotations

import importlib.metadata as md
import platform
import sqlite3

from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule
from sigma.modifiers import SigmaContainsModifier, SigmaEndswithModifier, SigmaStartswithModifier
from sigma.rule import SigmaDetection
from sigma.types import SigmaNumber, SigmaString

ALLOWED_MODIFIERS = {SigmaContainsModifier, SigmaEndswithModifier, SigmaStartswithModifier}
ALLOWED_CORRELATIONS = {"value_count"}  # add event_count only together with a self-test
DEFAULT_TS = "2026-01-01T00:00:00Z"
SEMANTICS = (
    "Sigma reference semantics via pySigma; ASCII case-insensitive; labelled synthetic events; "
    "field shapes assumed unless a claim cites a source"
)


class Unsupported(Exception):
    """A rule uses something the harness does not evaluate."""


def _walk_items(det):
    for item in det.detection_items:
        if isinstance(item, SigmaDetection):
            yield from _walk_items(item)
        else:
            yield item


def compile_rule(text: str):
    """Return (sql, fields, numeric_fields, is_correlation)."""
    try:
        col = SigmaCollection.from_yaml(text)
    except Exception as exc:  # parse errors are reported, never evaluated
        raise Unsupported(f"pySigma could not parse the file: {exc}") from exc
    fields, numeric = {"timestamp"}, set()
    is_correlation = False
    for r in col.rules:
        if isinstance(r, SigmaCorrelationRule):
            is_correlation = True
            if r.type.name.lower() not in ALLOWED_CORRELATIONS:  # .value is an int
                raise Unsupported(f"correlation type {r.type.name}")
            fields |= set(r.group_by or [])
            if r.condition.fieldref:
                fields.add(r.condition.fieldref)
            continue
        for det in r.detection.detections.values():
            for item in _walk_items(det):
                bad = [m.__name__ for m in item.modifiers if m not in ALLOWED_MODIFIERS]
                if bad:
                    raise Unsupported(f"modifier {bad} on {item.field}")
                for v in item.value:
                    if not isinstance(v, (SigmaString, SigmaNumber)):
                        raise Unsupported(f"value type {type(v).__name__} on {item.field}")
                    if isinstance(v, SigmaNumber) and item.field:
                        numeric.add(item.field)
                if item.field:
                    fields.add(item.field)
    try:
        queries = sqliteBackend().convert(col)
    except Exception as exc:
        raise Unsupported(f"pySigma sqlite backend: {exc}") from exc
    if len(queries) != 1:
        raise Unsupported(f"{len(queries)} queries")
    return queries[0], fields, numeric, is_correlation


def evaluate(sql: str, fields: set[str], events: list[dict]) -> bool:
    """True when the query returns at least one row over a fresh table holding `events`."""
    rows = [{k: v for k, v in e.items() if not k.startswith("_")} for e in events]
    cols = sorted(fields | {k for r in rows for k in r})
    db = sqlite3.connect(":memory:")
    try:
        # No type name, so values keep their own type; NOCASE gives Sigma's case-insensitive equality.
        db.execute("CREATE TABLE logs (" + ", ".join(f'"{c}" COLLATE NOCASE' for c in cols) + ")")
        for r in rows:
            r.setdefault("timestamp", DEFAULT_TS)
            db.execute(
                f'INSERT INTO logs ({", ".join(chr(34) + k + chr(34) for k in r)}) '
                f'VALUES ({", ".join("?" * len(r))})',
                list(r.values()),
            )
        return len(db.execute(sql).fetchall()) > 0
    finally:
        db.close()


def versions() -> dict:
    return {
        "pysigma": md.version("pySigma"),
        "backend": f"pySigma-backend-sqlite {md.version('pySigma-backend-sqlite')}",
        "sqlite": sqlite3.sqlite_version,
        "python": platform.python_version(),
        "semantics": SEMANTICS,
    }
