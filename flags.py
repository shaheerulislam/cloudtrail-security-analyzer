"""
Lightweight heuristic flags for parsed CloudTrail events.

This is intentionally simple — a handful of well-known suspicious patterns
analysts look for first. It's a preview of the rule engine we'll build next
(which will load rules from config/Sigma instead of hardcoding them here),
but it's useful on its own and makes the parser immediately demonstrate
security value rather than just being a plumbing exercise.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from models import CloudTrailEvent

# API calls commonly associated with privilege escalation or persistence.
SENSITIVE_IAM_ACTIONS = {
    "AttachUserPolicy",
    "AttachRolePolicy",
    "PutUserPolicy",
    "PutRolePolicy",
    "CreateAccessKey",
    "CreateLoginProfile",
    "UpdateAssumeRolePolicy",
}

# Actions that, if successful, mean someone turned off the security cameras.
LOG_TAMPERING_ACTIONS = {
    "StopLogging",
    "DeleteTrail",
    "UpdateTrail",
    "PutEventSelectors",
}


@dataclass
class Flag:
    event: CloudTrailEvent
    reason: str
    severity: str  # "low" | "medium" | "high"


def flag_event(event: CloudTrailEvent) -> list[Flag]:
    """Return zero or more heuristic flags for a single event."""
    flags: list[Flag] = []

    if event.is_root_user and not event.is_error:
        flags.append(
            Flag(event, "Root account used directly (best practice is to avoid this)", "high")
        )

    if event.is_console_login and event.mfa_authenticated is False:
        flags.append(Flag(event, "Console login without MFA", "high"))

    if event.event_name in LOG_TAMPERING_ACTIONS and not event.is_error:
        flags.append(
            Flag(event, f"Potential log tampering: {event.event_name}", "high")
        )

    if event.event_name in SENSITIVE_IAM_ACTIONS and not event.is_error:
        flags.append(
            Flag(event, f"Sensitive IAM change: {event.event_name}", "medium")
        )

    if event.is_console_login and event.is_error:
        flags.append(Flag(event, "Failed console login attempt", "low"))

    return flags


def flag_events(events: Iterable[CloudTrailEvent]) -> list[Flag]:
    """Run all heuristics across a collection of events."""
    all_flags: list[Flag] = []
    for event in events:
        all_flags.extend(flag_event(event))
    return all_flags