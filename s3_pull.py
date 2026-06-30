"""
Download real CloudTrail logs from S3 to a local folder, so they can be
fed into all_in_one.py / detect_standalone.py exactly like the sample data.

Usage:
    python s3_pull.py --bucket aws-cloudtrail-logs-122302353606-8b805ca8 --account-id 122302353606 --out ./real_logs
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("s3_pull")

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
except ImportError:
    print("boto3 is required. Install it with: python -m pip install boto3")
    sys.exit(1)


def main() -> int:
    parser = argparse.ArgumentParser(description="Download CloudTrail logs from S3.")
    parser.add_argument("--bucket", required=True, help="CloudTrail S3 bucket name")
    parser.add_argument("--account-id", required=True, help="Your AWS account ID")
    parser.add_argument("--region", default=None, help="AWS region (defaults to your CLI config)")
    parser.add_argument("--out", default="./real_logs", help="Local folder to save logs into")
    args = parser.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    prefix = f"AWSLogs/{args.account_id}/CloudTrail/"

    s3 = boto3.client("s3", region_name=args.region)

    try:
        paginator = s3.get_paginator("list_objects_v2")
        keys = []
        for page in paginator.paginate(Bucket=args.bucket, Prefix=prefix):
            for obj in page.get("Contents", []):
                key = obj["Key"]
                if key.endswith(".json.gz"):
                    keys.append(key)
    except (ClientError, NoCredentialsError) as exc:
        logger.error("Failed to list objects in s3://%s/%s : %s", args.bucket, prefix, exc)
        return 1

    if not keys:
        logger.warning(
            "No .json.gz log files found yet under s3://%s/%s — "
            "CloudTrail typically takes 5-15 minutes to deliver the first batch. Try again shortly.",
            args.bucket, prefix,
        )
        return 0

    logger.info("Found %d log file(s). Downloading to %s ...", len(keys), out_dir)

    for key in keys:
        local_path = out_dir / Path(key).name
        try:
            s3.download_file(args.bucket, key, str(local_path))
            logger.info("Downloaded %s", local_path.name)
        except ClientError as exc:
            logger.warning("Failed to download %s: %s", key, exc)

    logger.info("Done. %d file(s) saved to %s", len(keys), out_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())