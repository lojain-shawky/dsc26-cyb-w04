from __future__ import annotations

import argparse
import json
import sys
from datetime import date

from . import core


def _group_obj(g: core.Group) -> dict:
    return {
        "key": g.key,
        "path": g.path,
        "line": g.line,
        "severity": g.severity,
        "tools": g.tools,
        "fingerprints": g.fingerprints,
    }


def _load_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="triage")
    ap.add_argument("--sarif", required=True)
    ap.add_argument("--bandit", required=True)
    ap.add_argument("--project", required=True)
    ap.add_argument("--equivalences")
    ap.add_argument("--baseline")
    ap.add_argument("--suppressions")
    ap.add_argument("--today")
    ap.add_argument("--fail-on", default="high", choices=core.SEVERITIES)
    args = ap.parse_args(argv)

    try:
        today = date.fromisoformat(args.today) if args.today else date.today()
        findings = core.load_semgrep_sarif(args.sarif, args.project)
        findings += core.load_bandit(args.bandit, args.project)
        equivalences = _load_json(args.equivalences) if args.equivalences else {}
        baseline = set(_load_json(args.baseline)) if args.baseline else set()
        sup_entries = _load_json(args.suppressions) if args.suppressions else []
        if not isinstance(equivalences, dict) or not isinstance(sup_entries, list):
            raise ValueError("bad input shape")
    except (OSError, ValueError, TypeError, AttributeError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    groups = core.dedupe(findings, equivalences)
    sups, invalid = core.load_suppressions(sup_entries)
    active, suppressed = core.apply_suppressions(groups, sups, today)
    new, existing, fixed = core.diff_baseline(active, baseline)
    passed = core.gate(new, args.fail_on)

    print(json.dumps({
        "passed": passed,
        "new": [_group_obj(g) for g in new],
        "existing": [_group_obj(g) for g in existing],
        "suppressed": [_group_obj(g) for g in suppressed],
        "fixed": fixed,
        "invalid_suppressions": len(invalid),
    }, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
