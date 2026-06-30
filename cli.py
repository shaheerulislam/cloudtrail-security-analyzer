"""
Command-line entry point for the CloudTrail parser.

Usage:
    # Parse local CloudTrail log files (directory of .json/.json.gz)
    python cli.py --source local --path ./sample_logs --out events.csv

    # Parse logs directly from S3
    python cli.py --source s3 --bucket my-cloudtrail-bucket --prefix AWSLogs/ --out events.csv
"""

from __future__ import annotations

import argparse
import csv
import logging
import sys
from pathlib import Path

from flags import flag_events
from models import CloudTrailEvent
from parser import parse_directory

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("cli")


def write_csv(events: list[CloudTrailEvent], out_path: Path) -> None:
    if not events:
        logger.warning("No events to write.")
        return

    fieldnames = list(events[0].to_dict().keys())
    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for event in events:
            writer.writerow(event.to_dict())

    logger.info("Wrote %d events to %s", len(events), out_path)


def print_flag_summary(events: list[CloudTrailEvent]) -> None:
    flags = flag_events(events)
    if not flags:
        print("\nNo heuristic flags raised.")
        return

    print(f"\n{len(flags)} heuristic flag(s) raised:\n")
    for f in sorted(flags, key=lambda x: {"high": 0, "medium": 1, "low": 2}[x.severity]):
        print(
            f"  [{f.severity.upper():6}] {f.event.event_time.isoformat()} "
            f"{f.event.user_name or f.event.user_identity_type} -> "
            f"{f.event.event_name} :: {f.reason}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description="Parse AWS CloudTrail logs.")
    parser.add_argument(
        "--source", choices=["local", "s3"], default="local",
        help="Where to read logs from (default: local)",
    )
    parser.add_argument("--path", help="Local directory containing log files (--source local)")
    parser.add_argument("--bucket", help="S3 bucket name (--source s3)")
    parser.add_argument("--prefix", default="", help="S3 key prefix (--source s3)")
    parser.add_argument("--region", default=None, help="AWS region for S3 client")
    parser.add_argument("--out", default="events.csv", help="Output CSV path")

    args = parser.parse_args()

    if args.source == "local":
        if not args.path:
            parser.error("--path is required when --source local")
        events = list(parse_directory(args.path))
    else:
        if not args.bucket:
            parser.error("--bucket is required when --source s3")
        from s3_loader import parse_s3_logs  # imported lazily; needs boto3
        events = list(parse_s3_logs(args.bucket, args.prefix, args.region))

    if not events:
        logger.error("No events were parsed. Check your source path/bucket.")
        return 1

    write_csv(events, Path(args.out))
    print_flag_summary(events)
    return 0


if __name__ == "__main__":
    sys.exit(main())