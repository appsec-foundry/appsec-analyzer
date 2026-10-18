"""Deterministic scoring policy, catalog routing and calculation."""

from __future__ import annotations

import collections
import functools
import hashlib
import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from appsec_analyzer import resource_root
from appsec_analyzer.engine import initialize

# Points per architecture-coverage status. `not_applicable` never reaches here —
# it is what keeps the denominator honest.
STATUS_POINTS = {
    "present": 1.0,
    "partial": 0.5,
    "weak": 0.25,
    "missing": 0.0,
    "anti_pattern": 0.0,
}

# Catalog severity → penalty points, summed into a raw weight. Low is absent on
# purpose: every Low check in the config catalog states a build practice (SBOM
# generation, a Renovate config, a Dockerfile HEALTHCHECK) rather than a
# weakness, and a security indication should not move on those.
SEVERITY_WEIGHT = {"critical": 8.0, "high": 4.0, "medium": 1.5}

# Repeated hits of one CONFIG check are damped to `weight * (1 + ln(n))`. A
# repository property evaluated per file — a missing workflow `permissions:`
# block, an unsigned image — fires once per workflow, and counted per hit five
# such checks made up 78% of the raw weight on a measured repository. One policy
# gap is one thing to fix. Source findings are not damped: a weakness at
# seventeen call sites is seventeen places to change.
DAMPED_SCANNERS = frozenset({"config-iac"})

# Per indicator, the raw weight is mapped through `CAP * raw / (raw + HALF)`
# rather than being clipped. A hard cap saturates: measured on two repositories,
# both ran past it and the penalty stopped separating them. The curve keeps the
# low end apart and flattens where "many findings" stops being a new statement.
# The cap spans the whole scale on purpose: an indicator carrying dozens of
# confirmed findings is not rescued by a rule reporting the control as present.
PENALTY_CAP = 100.0
PENALTY_HALF_WEIGHT = 40.0

# Below this many applicable rules the sample is too small to divide by.
MIN_APPLICABLE_RULES = 5

# How many distinct checks the finding list names.
TOP_FINDINGS = 10

# A rule's decision caps the control credit its status can earn: a hypothesis is
# not a control, and a threat candidate is a control that failed.
DECISION_CEILING = {
    "emit_control_only": 1.0,
    "emit_control_and_hypothesis": 0.25,
    "emit_hypothesis_only": 0.25,
    "emit_control_and_threat_candidate": 0.0,
    "emit_anti_pattern_candidate": 0.0,
}

# The indicator vocabulary and its CWE / weakness-class routing.
_INDICATORS_YAML = resource_root() / "data" / "security-score-indicators.yaml"
_RULES_YAML = resource_root() / "data" / "architecture-coverage-rules.yaml"


def _load_yaml(path: Path) -> dict[str, Any]:
    try:
        import yaml

        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:  # noqa: BLE001 — a missing catalog degrades, never crashes
        return {}
    return doc if isinstance(doc, dict) else {}


@functools.lru_cache(maxsize=1)
def indicators() -> tuple[list[tuple[str, str]], dict[str, dict[str, str]], str]:
    """The indicator vocabulary: (order, routing tables, default).

    Routing tables are keyed by field name and consumed in the order
    :func:`indicator_for` applies them.
    """
    doc = _load_yaml(_INDICATORS_YAML)
    order: list[tuple[str, str]] = []
    tables: dict[str, dict[str, str]] = {
        field: {} for field in ("config_checks", "iac_types", "cwes", "weakness_classes", "scanners")
    }
    for entry in doc.get("indicators") or []:
        if not isinstance(entry, dict) or not entry.get("id"):
            continue
        indicator = str(entry["id"])
        order.append((indicator, str(entry.get("label") or indicator)))
        for field, table in tables.items():
            for value in entry.get(field) or []:
                key = str(value).strip()
                table.setdefault(key.upper() if field == "cwes" else key, indicator)
    return order, tables, str(doc.get("default") or "other")


@functools.lru_cache(maxsize=1)
def rule_cwes() -> dict[str, str]:
    """Rule id → CWE, from the coverage catalog; the rule output omits it."""
    doc = _load_yaml(_RULES_YAML)
    mapping: dict[str, str] = {}
    for family in ("hard_rules", "hypothesis_rules"):
        for rule in doc.get(family) or []:
            if isinstance(rule, dict) and rule.get("id") and rule.get("cwe"):
                mapping[str(rule["id"])] = str(rule["cwe"])
    return mapping


@dataclass(frozen=True)
class ScoringPolicy:
    """Loaded scoring catalogs; calculation itself does not access files."""

    indicators: tuple[tuple[str, str], ...]
    routing: dict[str, dict[str, str]]
    default: str
    rule_cwes: dict[str, str]
    weakness_by_cwe: dict[str, str]
    catalog_fingerprint: str


def load_policy() -> ScoringPolicy:
    """Load the bundled vocabulary and fingerprint before calculation."""
    initialize()
    from analyzers.weakness_classifier import classify_cwe

    catalogs = sorted((resource_root() / "data").glob("*-checks.yaml"))
    weakness = resource_root() / "data" / "weakness-classes.yaml"
    catalogs += [_INDICATORS_YAML, _RULES_YAML, weakness]
    digest = hashlib.sha256()
    for path in catalogs:
        digest.update(path.name.encode())
        digest.update(path.read_bytes())
    vocabulary = _load_yaml(weakness)
    cwes = {str(cwe).strip().upper() for cluster in vocabulary.get("clusters", []) for cwe in cluster.get("cwes", [])}
    classes = {cwe: classify_cwe(cwe, vocabulary, warn=False) for cwe in cwes}
    order, routing, default = indicators()
    return ScoringPolicy(tuple(order), routing, default, rule_cwes(), classes, digest.hexdigest())


def indicator_for(
    cwes: list[str],
    scanner: str | None = None,
    check_id: str | None = None,
    iac_type: str | None = None,
    *,
    policy: ScoringPolicy | None = None,
) -> str:
    """Route one item to its indicator; see the catalog for the order.

    A config/IaC check is placed by its identity and family before its CWE is
    consulted, because that CWE describes the weakness in the pipeline, not the
    aspect of the application a reader is looking at.
    """
    policy = policy or load_policy()
    tables, default = policy.routing, policy.default
    if check_id and check_id in tables["config_checks"]:
        return tables["config_checks"][check_id]
    if iac_type and iac_type in tables["iac_types"]:
        return tables["iac_types"][iac_type]
    normalized = [str(cwe or "").strip().upper() for cwe in cwes if cwe]
    for cwe in normalized:
        if cwe in tables["cwes"]:
            return tables["cwes"][cwe]
    for cwe in normalized:
        weakness_class = policy.weakness_by_cwe.get(cwe, "_unmapped")
        if weakness_class in tables["weakness_classes"]:
            return tables["weakness_classes"][weakness_class]
    return tables["scanners"].get(scanner or "", default)


def finding_title(finding: dict, *, full: bool = False) -> str:
    """Prefer the producer's violation title; retain a legacy mitigation fallback."""
    title = str(finding.get("title") or finding.get("recommended_mitigation_title") or "")
    if finding.get("_scanner") != "config-iac":
        title = title.split(" — ")[0]
    return title[:49] + "…" if not full and len(title) > 50 else title


def top_findings(findings: list[dict], limit: int = TOP_FINDINGS, *, full_titles: bool = False) -> list[dict]:
    """The most severe distinct checks, each with one example location.

    Grouped by check rather than listed per hit: seventeen instances of one
    broken authorization check are one thing to fix, and listing them
    individually would fill the whole list with a single check.
    """
    order = list(SEVERITY_WEIGHT)
    groups: dict[str, dict[str, Any]] = {}
    for finding in findings:
        severity = str(finding.get("severity") or "").strip().lower()
        if severity not in SEVERITY_WEIGHT:
            continue
        key = str(finding.get("check_id") or finding.get("title") or "?")
        group = groups.setdefault(key, {"count": 0, "severity": severity, "finding": finding})
        group["count"] += 1
        if order.index(severity) < order.index(group["severity"]):
            group["severity"], group["finding"] = severity, finding

    rows = [
        {
            "severity": group["severity"],
            "title": finding_title(group["finding"], full=full_titles),
            "count": group["count"],
            "location": _location(group["finding"]),
        }
        for group in groups.values()
    ]
    rows.sort(key=lambda row: (order.index(row["severity"]), -row["count"], row["title"]))
    return rows[:limit]


def _location(finding: dict) -> str:
    file = str(finding.get("file") or "?")
    line = finding.get("line")
    return f"{file}:{line}" if line else file


def rule_signal(rule: dict) -> str:
    """What one applicable rule actually saw, in the reader's words.

    The status alone does not distinguish "a control is in place" from "signals
    are there and nothing proves a control", which is the difference the row
    below the score has to carry.
    """
    decision = str(rule.get("decision") or "")
    if rule["status"] == "anti_pattern" or "threat_candidate" in decision or "anti_pattern" in decision:
        return "anti-pattern"
    if "hypothesis" in decision:
        return "hypothesis"
    return {
        "present": "control",
        "partial": "partial control",
        "weak": "weak control",
        "missing": "no control",
    }.get(rule["status"], rule["status"])


def rule_points(rule: dict) -> float:
    """Control credit for one applicable rule.

    The status alone overrates a rule that only raised a hypothesis. A repository
    whose sinks are all reached through unsanitized input scores ``partial`` on
    the injection rules, because the deterministic layer cannot prove the flow —
    proving it is the STRIDE stage's job. Half credit for that reads as "halfway
    controlled", which is the opposite of what the rule saw. The rule's decision
    therefore caps its credit: a hypothesis is not a control, and a threat
    candidate is a control that failed.
    """
    points = STATUS_POINTS[rule["status"]]
    return min(points, DECISION_CEILING.get(str(rule.get("decision") or ""), 1.0))


def _cwe_list(item: dict) -> list[str]:
    raw = item.get("cwe")
    return [str(c) for c in raw] if isinstance(raw, list) else [str(raw)] if raw else []


def finding_indicator(finding: dict, *, policy: ScoringPolicy | None = None) -> str:
    """Route one scanner finding to its indicator."""
    return indicator_for(
        _cwe_list(finding),
        scanner=finding.get("_scanner"),
        check_id=str(finding.get("check_id") or "") or None,
        iac_type=str(finding.get("iac_type") or "") or None,
        policy=policy,
    )


def _tally(findings: list[dict]) -> tuple[dict[str, int], float]:
    """Per-severity counts and the damped raw severity weight of a finding set."""
    counts = {severity: 0 for severity in SEVERITY_WEIGHT}
    per_check: dict[tuple[str, str], int] = collections.Counter()
    raw = 0.0
    for finding in findings:
        severity = str(finding.get("severity") or "").strip().lower()
        if severity not in SEVERITY_WEIGHT:
            continue
        counts[severity] += 1
        if finding.get("_scanner") in DAMPED_SCANNERS:
            per_check[(str(finding.get("check_id") or finding.get("title") or "?"), severity)] += 1
        else:
            raw += SEVERITY_WEIGHT[severity]
    raw += sum(SEVERITY_WEIGHT[severity] * (1 + math.log(n)) for (_, severity), n in per_check.items())
    return counts, raw


def finding_penalty(raw_weight: float) -> float:
    """Saturating deduction for a raw severity weight."""
    return PENALTY_CAP * raw_weight / (raw_weight + PENALTY_HALF_WEIGHT)


def compute(rules: list[dict], findings: list[dict], *, policy: ScoringPolicy | None = None) -> dict[str, Any]:
    """Score the collected signals. Pure — no subprocesses, catalogs only.

    One score per security principle, from that principle's own rules and its
    own findings; the headline is their mean. A global penalty spread over the
    whole repository hid exactly what the breakdown is for — the category a
    repository actually fails in.
    """
    applicable = [r for r in rules if r.get("status") in STATUS_POINTS]
    counts, _ = _tally(findings)

    result: dict[str, Any] = {
        "checks_total": len(rules),
        "checks_applicable": len(applicable),
        "findings": counts,
        "findings_total": sum(counts.values()),
        "categories": [],
    }

    policy = policy or load_policy()
    applicable_ids = sorted(str(rule.get("rule_id", "")) for rule in applicable)
    result["comparability"] = {
        "scoring_version": 2,
        "catalog_fingerprint": policy.catalog_fingerprint,
        "applicable_rules": applicable_ids,
        "coverage_fingerprint": hashlib.sha256(json.dumps(applicable_ids).encode()).hexdigest(),
    }
    result["excluded_findings"] = dict(
        collections.Counter(
            str(f.get("severity", "unknown")).lower()
            for f in findings
            if str(f.get("severity", "")).lower() not in SEVERITY_WEIGHT
        )
    )
    result["unscored_findings"] = {}
    if len(applicable) < MIN_APPLICABLE_RULES:
        result["verdict"] = "undetermined"
        result["score"] = None
        result["reason"] = (
            f"only {len(applicable)} of {len(rules)} checks applied to this repository "
            f"({MIN_APPLICABLE_RULES} required) — the rule catalog does not cover it"
        )
    else:
        result["verdict"] = "scored"

    order, cwe_by_rule = policy.indicators, policy.rule_cwes
    buckets: dict[str, dict[str, Any]] = {
        indicator: {"points": [], "signals": [], "findings": []} for indicator, _ in order
    }

    def bucket_for(key: str) -> dict[str, Any]:
        return buckets.setdefault(key, {"points": [], "signals": [], "findings": []})

    for rule in applicable:
        cwe = cwe_by_rule.get(str(rule.get("rule_id") or ""))
        bucket = bucket_for(indicator_for([cwe] if cwe else [], policy=policy))
        bucket["points"].append(rule_points(rule))
        bucket["signals"].append(rule_signal(rule))
    for finding in findings:
        bucket_for(finding_indicator(finding, policy=policy))["findings"].append(finding)

    known = {indicator for indicator, _ in order}
    categories = []
    for indicator, label in [*order, *((key, key) for key in buckets if key not in known)]:
        bucket = buckets[indicator]
        points = bucket["points"]
        if not points and not bucket["findings"]:
            continue
        found_counts, raw = _tally(bucket["findings"])
        # An indicator no rule applied to has no control evidence. It still
        # shows its findings, but scoring it would mean scoring an absence.
        control = 100.0 * sum(points) / len(points) if points else None
        categories.append(
            {
                "indicator": indicator,
                "label": label,
                "score": None if control is None else max(0, round(control - finding_penalty(raw))),
                "checks": len(points),
                "signals": dict(collections.Counter(bucket["signals"])),
                "findings": sum(found_counts.values()),
                "severities": {k: v for k, v in found_counts.items() if v},
            }
        )

    categories.sort(key=lambda row: (row["score"] is None, row["score"], row["label"]))
    result["categories"] = categories
    unscored = collections.Counter()
    for row in categories:
        if row["score"] is None:
            unscored.update(row["severities"])
    result["unscored_findings"] = dict(unscored)
    if result["verdict"] == "undetermined":
        return result

    # The weaker half decides. Averaging every category lets a well-covered area
    # pay for a broken one, which is not how a repository is attacked.
    scored = sorted(row["score"] for row in categories if row["score"] is not None)
    weaker_half = scored[: (len(scored) + 1) // 2]
    result["score"] = round(sum(weaker_half) / len(weaker_half))
    return result
