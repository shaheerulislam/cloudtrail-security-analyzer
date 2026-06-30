# CloudTrail Log Parser

A Python tool that parses AWS CloudTrail log files (local or from S3),
normalizes them into structured events, and flags common suspicious
patterns. This is the ingestion/parsing layer of a larger cloud security
analyst project — the detection rule engine and dashboard build on top
of this.

## Project structure

```
cloudtrail-parser/
├── models.py       # CloudTrailEvent dataclass - the normalized event schema
├── parser.py       # Core parsing logic for .json / .json.gz log files
├── s3_loader.py     # Optional S3 integration (requires boto3)
├── flags.py        # Lightweight heuristic flags (preview of the rule engine)
├── cli.py          # Command-line entry point
├── sample_logs/    # Example CloudTrail log with a realistic attack chain
└── requirements.txt
```

## Setup

```bash
pip install -r requirements.txt --break-system-packages
```

(boto3 is only needed if you use `--source s3`.)

## Usage

Parse local log files:

```bash
python cli.py --source local --path ./sample_logs --out events.csv
```

Parse logs directly from an S3 bucket:

```bash
python cli.py --source s3 --bucket my-cloudtrail-bucket --prefix AWSLogs/123456789012/CloudTrail/ --out events.csv
```

This will:
1. Parse every CloudTrail record into a structured `CloudTrailEvent`
2. Write all events to a CSV file
3. Print a summary of any heuristic security flags raised

## What it currently flags

- Root account usage (best practice: never use root for daily operations)
- Console logins without MFA
- Log tampering attempts (`StopLogging`, `DeleteTrail`, etc.)
- Sensitive IAM changes (`AttachUserPolicy`, `CreateAccessKey`, etc.)
- Failed console login attempts

These are intentionally simple heuristics. The next phase of the project
replaces `flags.py` with a proper rule engine (Sigma-style rules) and adds
correlation across multiple events (e.g. failed logins -> success -> IAM
change -> log tampering, as a single incident).

## Design notes

- **Separation of concerns**: `parser.py` has zero AWS SDK dependencies, so
  it can be unit tested without mocking S3 and reused for any CloudTrail
  JSON source (local export, CloudWatch Logs dump, etc).
- **Resilience**: malformed individual records are logged and skipped
  rather than crashing the whole batch — real-world log data is never
  perfectly clean.
- **Streaming-friendly**: `s3_loader.py` downloads and deletes one file at
  a time, so it scales to large log volumes without filling up disk.

## Next steps

- [ ] Threat detection rule engine (Sigma rules)
- [ ] Correlation logic for multi-step attack chains
- [ ] Output to OpenSearch instead of / in addition to CSV
- [ ] Lambda handler wrapper for real-time processing via Kinesis