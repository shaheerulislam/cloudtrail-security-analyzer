"""
run_pipeline.py — automated CloudTrail detection pipeline runner

Pulls the latest CloudTrail logs from S3, runs the detection rule engine,
exports dashboard_data.json, and logs a summary. Designed to be called
on a schedule (Windows Task Scheduler, cron, etc.) so the dashboard
always reflects recent AWS account activity without manual intervention.

Usage:
    python run_pipeline.py

Configuration: edit the CONFIG block below or pass environment variables:
    CT_BUCKET       S3 bucket name
    CT_ACCOUNT_ID   AWS account ID
    CT_REGION       AWS region (default eu-north-1)
    CT_RULES_DIR    Path to rules directory (default ./rules)
    CT_LOGS_DIR     Path to store downloaded logs (default ./real_logs)
    CT_JSON_OUT     Path for dashboard JSON output (default ./dashboard_data.json)
    CT_LOG_FILE     Path for pipeline log file (default ./pipeline.log)
"""

from __future__ import annotations

import gzip
import json
import logging
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Union

import yaml

# ============================================================
# CONFIG — edit these or set environment variables
# ============================================================
CONFIG = {
    "bucket":     os.environ.get("CT_BUCKET",     "aws-cloudtrail-logs-122302353606-8b805ca8"),
    "account_id": os.environ.get("CT_ACCOUNT_ID", "122302353606"),
    "region":     os.environ.get("CT_REGION",     "eu-north-1"),
    "rules_dir":  os.environ.get("CT_RULES_DIR",  "./rules"),
    "logs_dir":   os.environ.get("CT_LOGS_DIR",   "./real_logs"),
    "json_out":   os.environ.get("CT_JSON_OUT",   "./dashboard_data.json"),
    "log_file":   os.environ.get("CT_LOG_FILE",   "./pipeline.log"),
}
# ============================================================

# Logging — writes to both file and console
log_handlers = [
    logging.FileHandler(CONFIG["log_file"], encoding="utf-8"),
    logging.StreamHandler(sys.stdout),
]
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=log_handlers,
)
logger = logging.getLogger("pipeline")

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
except ImportError:
    logger.error("boto3 not installed. Run: python -m pip install boto3")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Step 1 — Pull logs from S3
# ---------------------------------------------------------------------------

def pull_s3_logs(bucket: str, account_id: str, region: str, logs_dir: Path) -> int:
    logs_dir.mkdir(parents=True, exist_ok=True)
    prefix = f"AWSLogs/{account_id}/CloudTrail/"
    s3 = boto3.client("s3", region_name=region)

    try:
        paginator = s3.get_paginator("list_objects_v2")
        keys = [
            obj["Key"]
            for page in paginator.paginate(Bucket=bucket, Prefix=prefix)
            for obj in page.get("Contents", [])
            if obj["Key"].endswith(".json.gz")
        ]
    except (ClientError, NoCredentialsError) as exc:
        logger.error("Failed to list S3 objects: %s", exc)
        return 0

    if not keys:
        logger.warning("No CloudTrail log files found in s3://%s/%s", bucket, prefix)
        return 0

    downloaded = 0
    for key in keys:
        local_path = logs_dir / Path(key).name
        if local_path.exists():
            continue  # already downloaded, skip
        try:
            s3.download_file(bucket, key, str(local_path))
            downloaded += 1
        except ClientError as exc:
            logger.warning("Failed to download %s: %s", key, exc)

    logger.info("S3 pull: %d new file(s) downloaded (%d total in bucket)", downloaded, len(keys))
    return len(keys)


# ---------------------------------------------------------------------------
# Step 2 — Parse logs
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
    uid = record.get("userIdentity", {}) or {}
    return CloudTrailEvent(
        event_id=record.get("eventID", ""),
        event_time=_parse_event_time(record["eventTime"]),
        event_name=record.get("eventName", ""),
        user_identity_type=uid.get("type", "Unknown"),
        user_name=uid.get("userName"),
        access_key_id=uid.get("accessKeyId"),
        raw=record,
    )


def parse_logs(logs_dir: Path) -> list[CloudTrailEvent]:
    events: list[CloudTrailEvent] = []
    for pattern in ("**/*.json", "**/*.json.gz"):
        for path in sorted(logs_dir.glob(pattern)):
            text = (
                gzip.open(path, "rt", encoding="utf-8").read()
                if path.suffix == ".gz"
                else path.read_text(encoding="utf-8")
            )
            payload = json.loads(text)
            for record in payload.get("Records", []):
                try:
                    events.append(_record_to_event(record))
                except (KeyError, ValueError):
                    pass
    logger.info("Parsed %d event(s) from %s", len(events), logs_dir)
    return events


# ---------------------------------------------------------------------------
# Step 3 — Detect
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
            id=data["id"], title=data["title"],
            description=data.get("description", "").strip(),
            severity=data.get("severity", "medium"),
            selection=data["detection"]["selection"],
            tags=data.get("tags", []),
        )


@dataclass
class Match:
    rule: Rule
    event: CloudTrailEvent


def load_rules(rules_dir: Path) -> list[Rule]:
    rules = []
    for path in sorted(list(rules_dir.glob("*.yml")) + list(rules_dir.glob("*.yaml"))):
        try:
            with path.open(encoding="utf-8") as f:
                rules.append(Rule.from_dict(yaml.safe_load(f)))
        except Exception as exc:
            logger.warning("Skipping invalid rule %s: %s", path.name, exc)
    logger.info("Loaded %d detection rule(s)", len(rules))
    return rules


def _get_nested(record: dict, path: str) -> Any:
    val: Any = record
    for part in path.split("."):
        val = val.get(part) if isinstance(val, dict) else None
    return val


def evaluate_events(rules: list[Rule], events: list[CloudTrailEvent]) -> list[Match]:
    matches = []
    for event in events:
        for rule in rules:
            if all(
                (_get_nested(event.raw, k) in v if isinstance(v, list) else _get_nested(event.raw, k) == v)
                for k, v in rule.selection.items()
            ):
                matches.append(Match(rule=rule, event=event))
    return matches


# ---------------------------------------------------------------------------
# Step 4 — Correlate
# ---------------------------------------------------------------------------

ATTACK_CHAINS = {
    "intrusion_and_cover_tracks": ["console_login_no_mfa", "iam_privilege_escalation", "cloudtrail_logging_disabled"],
    "root_compromise": ["root_console_login", "iam_privilege_escalation"],
    "persistence_and_defense_evasion": ["new_iam_user_created", "iam_privilege_escalation", "guardduty_disabled"],
    "data_exfiltration_setup": ["s3_bucket_public_access", "unauthorized_api_call"],
    "destructive_attack": ["kms_key_disabled_or_deleted", "cloudtrail_logging_disabled"],
}
CORRELATION_WINDOW = timedelta(minutes=30)


@dataclass
class Incident:
    chain_name: str
    actor: str
    matches: list[Match]
    severity: str = "critical"

    @property
    def start_time(self): return min(m.event.event_time for m in self.matches)
    @property
    def end_time(self): return max(m.event.event_time for m in self.matches)


def correlate(matches: list[Match]) -> list[Incident]:
    by_actor: dict[str, list[Match]] = {}
    for m in matches:
        key = m.event.user_name or m.event.access_key_id or m.event.user_identity_type
        by_actor.setdefault(key, []).append(m)

    incidents = []
    for actor, actor_matches in by_actor.items():
        rule_map = {m.rule.id: m for m in actor_matches}
        for chain_name, required in ATTACK_CHAINS.items():
            if not all(r in rule_map for r in required):
                continue
            chain = [rule_map[r] for r in required]
            window = max(m.event.event_time for m in chain) - min(m.event.event_time for m in chain)
            if window <= CORRELATION_WINDOW:
                incidents.append(Incident(chain_name=chain_name, actor=actor, matches=chain))
    return incidents


# ---------------------------------------------------------------------------
# Step 5 — Export JSON for dashboard
# ---------------------------------------------------------------------------

def export_json(events: list, matches: list[Match], incidents: list[Incident], out: Path) -> None:
    sc: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for m in matches:
        sc[m.rule.severity] = sc.get(m.rule.severity, 0) + 1

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_events": len(events),
            "total_matches": len(matches),
            "total_incidents": len(incidents),
            "severity_counts": sc,
        },
        "matches": [
            {
                "rule_id": m.rule.id, "rule_title": m.rule.title,
                "severity": m.rule.severity, "description": m.rule.description,
                "tags": m.rule.tags, "event_time": m.event.event_time.isoformat(),
                "event_name": m.event.event_name,
                "actor": m.event.user_name or m.event.user_identity_type,
            }
            for m in sorted(matches, key=lambda x: x.event.event_time)
        ],
        "incidents": [
            {
                "chain_name": inc.chain_name, "actor": inc.actor,
                "severity": inc.severity,
                "start_time": inc.start_time.isoformat(),
                "end_time": inc.end_time.isoformat(),
                "steps": [
                    {"rule_title": m.rule.title, "rule_id": m.rule.id,
                     "event_time": m.event.event_time.isoformat(), "severity": m.rule.severity}
                    for m in inc.matches
                ],
            }
            for inc in incidents
        ],
    }
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    logger.info("Exported dashboard data to %s", out)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    logger.info("=" * 60)
    logger.info("Pipeline run started")

    logs_dir = Path(CONFIG["logs_dir"])
    rules_dir = Path(CONFIG["rules_dir"])
    json_out  = Path(CONFIG["json_out"])

    total = pull_s3_logs(CONFIG["bucket"], CONFIG["account_id"], CONFIG["region"], logs_dir)
    if total == 0 and not any(logs_dir.glob("**/*.json*")):
        logger.error("No logs available — aborting.")
        return 1

    events  = parse_logs(logs_dir)
    rules   = load_rules(rules_dir)
    matches = evaluate_events(rules, events)
    incidents = correlate(matches)

    export_json(events, matches, incidents, json_out)

    logger.info(
        "Summary: %d events | %d matches | %d incidents",
        len(events), len(matches), len(incidents),
    )
    logger.info("Pipeline run complete")
    logger.info("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())