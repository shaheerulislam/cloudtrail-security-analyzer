"""
Data models for parsed CloudTrail events.

Keeping this as a dataclass (rather than passing raw dicts around) gives us
type hints, autocomplete, and a single place to evolve the schema as the
project grows (e.g. when we add detection-rule fields later).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional


@dataclass
class CloudTrailEvent:
    """A normalized, parser-friendly view of a single CloudTrail record."""

    event_id: str
    event_time: datetime
    event_name: str
    event_source: str
    aws_region: str
    source_ip: str
    user_agent: str

    # Identity fields
    user_identity_type: str
    user_name: Optional[str]
    account_id: Optional[str]
    access_key_id: Optional[str]
    mfa_authenticated: Optional[bool]

    # Outcome fields
    error_code: Optional[str]
    error_message: Optional[str]

    # Raw payloads kept for deeper inspection / debugging
    request_parameters: dict[str, Any] = field(default_factory=dict)
    response_elements: dict[str, Any] = field(default_factory=dict)

    # The full original record, in case a detection rule needs a field
    # we haven't promoted to a top-level attribute yet.
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @property
    def is_error(self) -> bool:
        return bool(self.error_code)

    @property
    def is_console_login(self) -> bool:
        return self.event_name == "ConsoleLogin"

    @property
    def is_root_user(self) -> bool:
        return self.user_identity_type == "Root"

    def to_dict(self) -> dict[str, Any]:
        """Flatten back to a plain dict, e.g. for writing to CSV/JSON/S3."""
        return {
            "event_id": self.event_id,
            "event_time": self.event_time.isoformat(),
            "event_name": self.event_name,
            "event_source": self.event_source,
            "aws_region": self.aws_region,
            "source_ip": self.source_ip,
            "user_agent": self.user_agent,
            "user_identity_type": self.user_identity_type,
            "user_name": self.user_name,
            "account_id": self.account_id,
            "access_key_id": self.access_key_id,
            "mfa_authenticated": self.mfa_authenticated,
            "error_code": self.error_code,
            "error_message": self.error_message,
            "is_error": self.is_error,
        }