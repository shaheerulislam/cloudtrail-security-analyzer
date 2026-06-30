"""
Sigma-style threat detection + correlation engine for CloudTrail logs.
Standalone version — combines the rule engine, correlation engine, and a
minimal CloudTrail parser into one file, so it works without needing the
other project files.

Usage:
    python detect_standalone.py --path ./sample_logs --rules ./rules
"""

from __future__ import annotations

import argparse
import gzip
import json
import logging
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Union

import yaml

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("detect")

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


# ---------------------------------------------------------------------------
# Minimal event model + parser
# ---------------------------------------------------------------------------

@dataclass
class CloudTrailEvent:
    event_id: str
    event_time: datetime
    event_name: str
    user_identity_type: str
    user_name: Union[str, None]
    access_key_id: Union[str, None]
    raw: dict = field(default_factory=dict, repr=False)


def _parse_event_time(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")


def _record_to_event(record: dict) -> CloudTrailEvent:
    user_identity = record.get("userIdentity", {}) or {}
    return CloudTrailEvent(
        event_id=record.get("eventID", ""),
        event_time=_parse_event_time(record["eventTime"]),
        event_name=record.get("eventName", ""),
        user_identity_type=user_identity.get("type", "Unknown"),
        user_name=user_identity.get("userName"),
        access_key_id=user_identity.get("accessKeyId"),
        raw=record,
    )


def parse_directory(directory: Union[str, Path]) -> list[CloudTrailEvent]:
    directory = Path(directory)
    events: list[CloudTrailEvent] = []

    for pattern in ("**/*.json", "**/*.json.gz"):
        for path in sorted(directory.glob(pattern)):
            text = (
                gzip.open(path, "rt", encoding="utf-8").read()
                if path.suffix == ".gz"
                else path.read_text(encoding="utf-8")
            )
            payload = json.loads(text)
            for record in payload.get("Records", []):
                try:
                    events.append(_record_to_event(record))
                except (KeyError, ValueError) as exc:
                    logger.warning("Skipping malformed record in %s: %s", path.name, exc)

    logger.info("Parsed %d event(s) from %s", len(events), directory)
    return events


# ---------------------------------------------------------------------------
# Rule engine
# ---------------------------------------------------------------------------

@dataclass
class Rule:
    id: str
    title: str
    description: str
    severity: str
    selection: dict
    tags: list

    @classmethod
    def from_dict(cls, data: dict) -> "Rule":
        return cls(
            id=data["id"],
            title=data["title"],
            description=data.get("description", "").strip(),
            severity=data.get("severity", "medium"),
            selection=data["detection"]["selection"],
            tags=data.get("tags", []),
        )


@dataclass
class Match:
    rule: Rule
    event: CloudTrailEvent


def load_rules(rules_dir: Union[str, Path]) -> list[Rule]:
    rules_dir = Path(rules_dir)
    rules: list[Rule] = []
    for path in sorted(list(rules_dir.glob("*.yml")) + list(rules_dir.glob("*.yaml"))):
        try:
            with path.open(encoding="utf-8") as f:
                data = yaml.safe_load(f)
            rules.append(Rule.from_dict(data))
        except (yaml.YAMLError, KeyError) as exc:
            logger.warning("Skipping invalid rule file %s: %s", path.name, exc)
    logger.info("Loaded %d detection rule(s) from %s", len(rules), rules_dir)
    return rules


def _get_nested(record: dict, dotted_path: str) -> Any:
    value: Any = record
    for part in dotted_path.split("."):
        if isinstance(value, dict):
            value = value.get(part)
        else:
            return None
    return value


def _field_matches(actual: Any, expected: Any) -> bool:
    if isinstance(expected, list):
        return actual in expected
    return actual == expected


def evaluate_rule(rule: Rule, raw_record: dict) -> bool:
    for field_path, expected in rule.selection.items():
        actual = _get_nested(raw_record, field_path)
        if not _field_matches(actual, expected):
            return False
    return True


def evaluate_events(rules: Iterable[Rule], events: Iterable[CloudTrailEvent]) -> list[Match]:
    matches: list[Match] = []
    for event in events:
        for rule in rules:
            if evaluate_rule(rule, event.raw):
                matches.append(Match(rule=rule, event=event))
    return matches


# ---------------------------------------------------------------------------
# Correlation engine
# ---------------------------------------------------------------------------

ATTACK_CHAINS: dict[str, list[str]] = {
    "intrusion_and_cover_tracks": [
        "console_login_no_mfa",
        "iam_privilege_escalation",
        "cloudtrail_logging_disabled",
    ],
    "root_compromise": [
        "root_console_login",
        "iam_privilege_escalation",
    ],
    "persistence_and_defense_evasion": [
        "new_iam_user_created",
        "iam_privilege_escalation",
        "guardduty_disabled",
    ],
    "data_exfiltration_setup": [
        "s3_bucket_public_access",
        "unauthorized_api_call",
    ],
    "destructive_attack": [
        "kms_key_disabled_or_deleted",
        "cloudtrail_logging_disabled",
    ],
}

CORRELATION_WINDOW = timedelta(minutes=30)


@dataclass
class Incident:
    chain_name: str
    actor: str
    matches: list[Match]
    severity: str = "critical"

    @property
    def start_time(self):
        return min(m.event.event_time for m in self.matches)

    @property
    def end_time(self):
        return max(m.event.event_time for m in self.matches)


def _actor_key(match: Match) -> str:
    event = match.event
    return event.user_name or event.access_key_id or event.user_identity_type


def correlate(matches: Iterable[Match]) -> list[Incident]:
    by_actor: dict[str, list[Match]] = {}
    for m in matches:
        by_actor.setdefault(_actor_key(m), []).append(m)

    incidents: list[Incident] = []
    for actor, actor_matches in by_actor.items():
        actor_matches.sort(key=lambda m: m.event.event_time)
        matched_rule_ids = {m.rule.id: m for m in actor_matches}

        for chain_name, required_rule_ids in ATTACK_CHAINS.items():
            if not all(rid in matched_rule_ids for rid in required_rule_ids):
                continue
            chain_matches = [matched_rule_ids[rid] for rid in required_rule_ids]
            window = max(m.event.event_time for m in chain_matches) - min(
                m.event.event_time for m in chain_matches
            )
            if window <= CORRELATION_WINDOW:
                incidents.append(Incident(chain_name=chain_name, actor=actor, matches=chain_matches))

    return incidents


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def print_matches(matches: list[Match]) -> None:
    if not matches:
        print("\nNo rule matches.")
        return
    matches_sorted = sorted(matches, key=lambda m: SEVERITY_ORDER.get(m.rule.severity, 9))
    print(f"\n{len(matches)} rule match(es):\n")
    for m in matches_sorted:
        actor = m.event.user_name or m.event.user_identity_type
        print(
            f"  [{m.rule.severity.upper():8}] {m.event.event_time.isoformat()} "
            f"{actor:15} {m.rule.title} ({m.rule.id})"
        )


def print_incidents(incidents: list[Incident]) -> None:
    if not incidents:
        print("\nNo correlated incidents detected.")
        return
    print(f"\n{len(incidents)} CORRELATED INCIDENT(S) — multi-step attack chains:\n")
    for inc in incidents:
        print(f"  >>> [{inc.severity.upper()}] {inc.chain_name} — actor: {inc.actor}")
        print(f"      window: {inc.start_time.isoformat()} -> {inc.end_time.isoformat()}")
        for step_num, m in enumerate(inc.matches, start=1):
            print(f"      step {step_num}: {m.rule.title} at {m.event.event_time.isoformat()}")
        print()


def export_json(
    events: list[CloudTrailEvent],
    matches: list[Match],
    incidents: list[Incident],
    out_path: Path,
) -> None:
    """Export the full run as a single JSON file the HTML dashboard can load."""
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for m in matches:
        severity_counts[m.rule.severity] = severity_counts.get(m.rule.severity, 0) + 1

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_events": len(events),
            "total_matches": len(matches),
            "total_incidents": len(incidents),
            "severity_counts": severity_counts,
        },
        "matches": [
            {
                "rule_id": m.rule.id,
                "rule_title": m.rule.title,
                "severity": m.rule.severity,
                "description": m.rule.description,
                "tags": m.rule.tags,
                "event_time": m.event.event_time.isoformat(),
                "event_name": m.event.event_name,
                "actor": m.event.user_name or m.event.user_identity_type,
            }
            for m in sorted(matches, key=lambda m: m.event.event_time)
        ],
        "incidents": [
            {
                "chain_name": inc.chain_name,
                "actor": inc.actor,
                "severity": inc.severity,
                "start_time": inc.start_time.isoformat(),
                "end_time": inc.end_time.isoformat(),
                "steps": [
                    {
                        "rule_title": m.rule.title,
                        "rule_id": m.rule.id,
                        "event_time": m.event.event_time.isoformat(),
                        "severity": m.rule.severity,
                    }
                    for m in inc.matches
                ],
            }
            for inc in incidents
        ],
    }

    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    logger.info("Wrote dashboard data to %s", out_path)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run detection rules against CloudTrail logs.")
    parser.add_argument("--path", required=True, help="Directory of CloudTrail log files")
    parser.add_argument("--rules", default="./rules", help="Directory of YAML rule files")
    parser.add_argument(
        "--json-out", default="dashboard_data.json",
        help="Path to write JSON results for the HTML dashboard",
    )
    args = parser.parse_args()

    events = parse_directory(args.path)
    if not events:
        logger.error("No events parsed from %s", args.path)
        return 1

    rules = load_rules(args.rules)
    if not rules:
        logger.error("No rules loaded from %s", args.rules)
        return 1

    matches = evaluate_events(rules, events)
    incidents = correlate(matches)

    print_matches(matches)
    print_incidents(incidents)
    export_json(events, matches, incidents, Path(args.json_out))
    return 0


if __name__ == "__main__":
    sys.exit(main())