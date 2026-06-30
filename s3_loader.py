"""
S3 loader for CloudTrail logs.

Keeps AWS/boto3 concerns separate from parsing logic (parser.py has zero
AWS SDK dependencies, so it's easy to unit test without mocking S3, and
reusable if you ever ingest CloudTrail logs from another source like
CloudWatch Logs or a SIEM export).
"""

from __future__ import annotations

import logging
import tempfile
from pathlib import Path
from typing import Iterator, Optional

from models import CloudTrailEvent
from parser import CloudTrailParseError, parse_file

logger = logging.getLogger(__name__)

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:  # pragma: no cover - boto3 is an optional dependency
    boto3 = None
    ClientError = Exception


def _require_boto3() -> None:
    if boto3 is None:
        raise ImportError(
            "boto3 is required for S3 access. Install it with: "
            "pip install boto3 --break-system-packages"
        )


def iter_s3_log_keys(
    bucket: str,
    prefix: str = "",
    region_name: Optional[str] = None,
) -> Iterator[str]:
    """Yield S3 object keys under a bucket/prefix that look like CloudTrail logs."""
    _require_boto3()
    s3 = boto3.client("s3", region_name=region_name)
    paginator = s3.get_paginator("list_objects_v2")

    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            if key.endswith(".json.gz") or key.endswith(".json"):
                yield key


def parse_s3_logs(
    bucket: str,
    prefix: str = "",
    region_name: Optional[str] = None,
) -> Iterator[CloudTrailEvent]:
    """
    Download and parse every CloudTrail log object under bucket/prefix.

    Files are streamed one at a time into a temp directory and removed
    immediately after parsing, so this scales to large log volumes without
    accumulating disk usage.
    """
    _require_boto3()
    s3 = boto3.client("s3", region_name=region_name)

    keys = list(iter_s3_log_keys(bucket, prefix, region_name))
    logger.info("Found %d candidate log files in s3://%s/%s", len(keys), bucket, prefix)

    with tempfile.TemporaryDirectory(prefix="cloudtrail_") as tmp_dir:
        tmp_path = Path(tmp_dir)
        for key in keys:
            local_file = tmp_path / Path(key).name
            try:
                s3.download_file(bucket, key, str(local_file))
            except ClientError as exc:
                logger.warning("Failed to download s3://%s/%s: %s", bucket, key, exc)
                continue

            try:
                yield from parse_file(local_file)
            except CloudTrailParseError as exc:
                logger.warning("Skipping unparsable object %s: %s", key, exc)
            finally:
                local_file.unlink(missing_ok=True)