from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass, field
from datetime import date

SEVERITIES = ["info", "low", "medium", "high", "critical"]  # lowest to highest


@dataclass(frozen=True)
class Finding:
    tool: str
    rule_id: str
    path: str
    line: int
    severity: str
    cwe: int | None
    message: str
    code: str


def fingerprint(f: Finding) -> str:
    code = " ".join(f.code.split())
    raw = f"{f.tool}|{f.rule_id}|{f.path}|{code}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@dataclass
class Group:
    key: str
    path: str
    line: int
    severity: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def tools(self) -> list[str]:
        return sorted({f.tool for f in self.findings})

    @property
    def fingerprints(self) -> list[str]:
        return sorted({fingerprint(f) for f in self.findings})


@dataclass(frozen=True)
class Suppression:
    fingerprint: str
    reason: str
    expires: date
    by: str


# ---------------------------------------------------------------- paths

def normalize_path(raw: str, project: str) -> str:
    p = raw.replace("\\", "/")
    if p.startswith("file://"):
        p = p[len("file://"):]
    segs = [s for s in p.split("/") if s not in ("", ".")]
    if project and project in segs:
        idx = len(segs) - 1 - segs[::-1].index(project)
        segs = segs[idx + 1:]
    return "/".join(segs)


# ---------------------------------------------------------------- loaders

def _read_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _score_to_severity(value) -> str | None:
    if isinstance(value, bool):
        return None
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    if math.isnan(score) or not (0 < score <= 10):
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


_LEVELS = {"error": "high", "warning": "medium", "note": "low", "none": "info"}


def load_semgrep_sarif(path, project: str) -> list[Finding]:
    data = _read_json(path)
    findings: list[Finding] = []
    for run in data.get("runs", []) or []:
        driver = ((run.get("tool") or {}).get("driver")) or {}
        rules = driver.get("rules") or []
        by_id = {r.get("id"): r for r in rules if isinstance(r, dict)}
        for res in run.get("results", []) or []:
            rule_id = res.get("ruleId") or (res.get("rule") or {}).get("id") or ""
            rule = by_id.get(rule_id, {})
            props = rule.get("properties") or {}

            sev = _score_to_severity(props.get("security-severity"))
            if sev is None:
                level = (
                    res.get("level")
                    or (rule.get("defaultConfiguration") or {}).get("level")
                    or "warning"
                )
                sev = _LEVELS.get(level, "medium")

            cwe = None
            for tag in props.get("tags") or []:
                m = re.match(r"CWE-(\d+)", str(tag))
                if m:
                    cwe = int(m.group(1))
                    break

            locs = res.get("locations") or [{}]
            phys = (locs[0] or {}).get("physicalLocation") or {}
            uri = (phys.get("artifactLocation") or {}).get("uri", "")
            region = phys.get("region") or {}
            snippet = (region.get("snippet") or {}).get("text") or ""
            code = snippet.split("\n")[0].rstrip("\r") if snippet else ""

            findings.append(
                Finding(
                    tool="semgrep",
                    rule_id=rule_id,
                    path=normalize_path(uri, project),
                    line=int(region.get("startLine", 0) or 0),
                    severity=sev,
                    cwe=cwe,
                    message=(res.get("message") or {}).get("text", ""),
                    code=code,
                )
            )
    return findings


_BANDIT_SEV = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}


def _bandit_code_line(block: str, line_number: int) -> str:
    for raw in (block or "").split("\n"):
        raw = raw.rstrip("\r")
        num, _, text = raw.partition(" ")
        if num.isdigit() and int(num) == line_number:
            return text
    return ""


def load_bandit(path, project: str) -> list[Finding]:
    data = _read_json(path)
    findings: list[Finding] = []
    for r in data.get("results", []) or []:
        sev = _BANDIT_SEV.get(str(r.get("issue_severity", "")).upper(), "info")
        if str(r.get("issue_confidence", "")).upper() == "LOW":
            sev = SEVERITIES[max(SEVERITIES.index(sev) - 1, 0)]

        cwe_obj = r.get("issue_cwe")
        cwe = None
        if isinstance(cwe_obj, dict) and cwe_obj.get("id") is not None:
            try:
                cwe = int(cwe_obj["id"])
            except (TypeError, ValueError):
                cwe = None

        line = int(r.get("line_number", 0) or 0)
        findings.append(
            Finding(
                tool="bandit",
                rule_id=r.get("test_id", ""),
                path=normalize_path(r.get("filename", ""), project),
                line=line,
                severity=sev,
                cwe=cwe,
                message=r.get("issue_text", ""),
                code=_bandit_code_line(r.get("code", ""), line),
            )
        )
    return findings


# ---------------------------------------------------------------- dedupe

def issue_key(f: Finding, equivalences: dict[str, str]) -> str:
    k = f"{f.tool}:{f.rule_id}"
    if k in equivalences:
        return equivalences[k]
    if f.cwe is not None:
        return f"CWE-{f.cwe}"
    return k


def dedupe(findings: list[Finding],
           equivalences: dict[str, str] | None = None) -> list[Group]:
    eq = equivalences or {}
    buckets: dict[tuple[str, int, str], list[Finding]] = {}
    for f in findings:
        buckets.setdefault((f.path, f.line, issue_key(f, eq)), []).append(f)

    groups = []
    for (path, line, key), members in buckets.items():
        members = sorted(members, key=lambda m: (m.tool, m.rule_id, fingerprint(m),
                                                 m.message, m.severity))
        top = max(members, key=lambda m: SEVERITIES.index(m.severity)).severity
        groups.append(Group(key=key, path=path, line=line, severity=top,
                            findings=members))

    groups.sort(key=lambda g: (-SEVERITIES.index(g.severity), g.path, g.line, g.key))
    return groups


# ---------------------------------------------------------------- suppressions

_HEX64 = re.compile(r"[0-9a-f]{64}")


def load_suppressions(entries: list[dict]) -> tuple[list[Suppression], list[dict]]:
    valid: list[Suppression] = []
    invalid: list[dict] = []
    for e in entries:
        try:
            fp = e["fingerprint"]
            reason = e["reason"]
            by = e["by"]
            exp = e["expires"]
            if not (isinstance(fp, str) and _HEX64.fullmatch(fp)):
                raise ValueError("fingerprint")
            if not (isinstance(reason, str) and len(reason.strip()) >= 10):
                raise ValueError("reason")
            if not (isinstance(by, str) and by.strip()):
                raise ValueError("by")
            if not isinstance(exp, str):
                raise ValueError("expires")
            valid.append(Suppression(fp, reason, date.fromisoformat(exp), by))
        except (KeyError, TypeError, ValueError, AttributeError):
            invalid.append(e)
    return valid, invalid


def apply_suppressions(groups, suppressions, today: date):
    live = {s.fingerprint for s in suppressions if s.expires >= today}
    active, suppressed = [], []
    for g in groups:
        if any(fp in live for fp in g.fingerprints):
            suppressed.append(g)
        else:
            active.append(g)
    return active, suppressed


# ---------------------------------------------------------------- baseline / gate

def diff_baseline(groups, baseline: set[str]):
    baseline = set(baseline)
    new, existing = [], []
    seen: set[str] = set()
    for g in groups:
        fps = g.fingerprints
        seen.update(fps)
        (existing if any(fp in baseline for fp in fps) else new).append(g)
    fixed = sorted(baseline - seen)
    return new, existing, fixed


def gate(new_active: list[Group], fail_on: str) -> bool:
    threshold = SEVERITIES.index(fail_on)
    return not any(SEVERITIES.index(g.severity) >= threshold for g in new_active)
