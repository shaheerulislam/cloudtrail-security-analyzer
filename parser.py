"""
Core CloudTrail log parsing logic.

CloudTrail delivers log files to S3 as gzipped JSON, each containing a
top-level "Records" array of individual events. This module knows how to:

  1. Read both .json and .json.gz files from local disk (S3 download is
     handled separately in s3_loader.py, keeping I/O concerns isolated
     from parsing logic).
  2. Validate and normalize each record into a CloudTrailEvent.
  3. Skip / log malformed records instead of crashing the whole batch,
     since real-world log data is never perfectly clean.
"""

from __future__ import annotations

import gzip
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Iterator, Union

from models import CloudTrailEvent

logger = logging.getLogger(__name__)


class CloudTrailParseError(Exception):
    """Raised when a log file can't be parsed at all (not a single record)."""


def _read_text(path: Path) -> str:
    """Read a .json or .json.gz file and return its raw text content."""
    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8") as f:
            return f.read()
    return path.read_text(encoding="utf-8")


def _parse_event_time(value: str) -> datetime:
    """CloudTrail timestamps are ISO 8601 UTC, e.g. '2023-07-19T21:35:03Z'."""
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")


def _record_to_event(record: dict) -> CloudTrailEvent:
    """Convert a single raw CloudTrail record dict into a CloudTrailEvent."""
    user_identity = record.get("userIdentity", {}) or {}
    session_ctx = user_identity.get("sessionContext", {}) or {}
    session_attrs = session_ctx.get("attributes", {}) or {}

    mfa_raw = session_attrs.get("mfaAuthenticated")
    mfa_authenticated = (
        mfa_raw.lower() == "true" if isinstance(mfa_raw, str) else None
    )

    return CloudTrailEvent(
        event_id=record.get("eventID", ""),
        event_time=_parse_event_time(record["eventTime"]),
        event_name=record.get("eventName", ""),
        event_source=record.get("eventSource", ""),
        aws_region=record.get("awsRegion", ""),
        source_ip=record.get("sourceIPAddress", ""),
        user_agent=record.get("userAgent", ""),
        user_identity_type=user_identity.get("type", "Unknown"),
        user_name=user_identity.get("userName"),
        account_id=user_identity.get("accountId"),
        access_key_id=user_identity.get("accessKeyId"),
        mfa_authenticated=mfa_authenticated,
        error_code=record.get("errorCode"),
        error_message=record.get("errorMessage"),
        request_parameters=record.get("requestParameters") or {},
        response_elements=record.get("responseElements") or {},
        raw=record,
    )


def parse_file(path: Union[str, Path]) -> list[CloudTrailEvent]:
    """
    Parse a single CloudTrail log file (.json or .json.gz) into a list of
    CloudTrailEvent objects. Malformed individual records are skipped and
    logged rather than aborting the whole file.
    """
    path = Path(path)
    text = _read_text(path)

    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise CloudTrailParseError(f"{path} is not valid JSON: {exc}") from exc

    records = payload.get("Records")
    if records is None:
        raise CloudTrailParseError(f"{path} has no top-level 'Records' array")

    events: list[CloudTrailEvent] = []
    for i, record in enumerate(records):
        try:
            events.append(_record_to_event(record))
        except (KeyError, ValueError) as exc:
            logger.warning(
                "Skipping malformed record #%d in %s: %s", i, path.name, exc
            )

    logger.info("Parsed %d/%d records from %s", len(events), len(records), path.name)
    return events


def parse_directory(directory: Union[str, Path]) -> Iterator[CloudTrailEvent]:
    """
    Parse every .json / .json.gz file in a directory (non-recursive by
    default scope, but glob pattern below covers nested CloudTrail-style
    date partitions like AWSLogs/123456789012/CloudTrail/us-east-1/2024/...).
    """
    directory = Path(directory)
    patterns = ("**/*.json", "**/*.json.gz")

    found_any = False
    for pattern in patterns:
        for file_path in sorted(directory.glob(pattern)):
            found_any = True
            try:
                yield from parse_file(file_path)
            except CloudTrailParseError as exc:
                logger.warning("Skipping unparsable file: %s", exc)

    if not found_any:
        logger.warning("No CloudTrail log files found under %s", directory)