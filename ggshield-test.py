"""Analyze simple security events from a JSON Lines file.

Run without arguments to analyze the built-in demo events::

    python ggshield-test.py

Pass a JSONL file or request machine-readable output::

    python ggshield-test.py events.jsonl --threshold 2
    python ggshield-test.py --json
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


DEMO_EVENTS = (
    {
        "timestamp": "2026-09-04T08:00:00Z",
        "actor": "alice",
        "action": "login",
        "status": "success",
        "source_ip": "192.0.2.10",
    },
    {
        "timestamp": "2026-09-04T08:04:00Z",
        "actor": "bob",
        "action": "login",
        "status": "failed",
        "source_ip": "198.51.100.25",
    },
    {
        "timestamp": "2026-09-04T08:05:00Z",
        "actor": "bob",
        "action": "login",
        "status": "failed",
        "source_ip": "198.51.100.25",
    },
    {
        "timestamp": "2026-09-04T08:06:00Z",
        "actor": "bob",
        "action": "login",
        "status": "failed",
        "source_ip": "198.51.100.25",
    },
    {
        "timestamp": "2026-09-04T08:10:00Z",
        "actor": "alice",
        "action": "repository.read",
        "status": "success",
        "source_ip": "192.0.2.10",
    },
)


@dataclass(frozen=True, slots=True)
class SecurityEvent:
    """Normalized representation of one security event."""

    timestamp: datetime
    actor: str
    action: str
    status: str
    source_ip: str

    @classmethod
    def from_mapping(cls, raw: dict[str, Any]) -> "SecurityEvent":
        """Validate and convert a JSON object into a security event."""
        required = ("timestamp", "actor", "action", "status", "source_ip")
        missing = [field for field in required if not raw.get(field)]
        if missing:
            raise ValueError(f"missing required fields: {', '.join(missing)}")

        timestamp_text = str(raw["timestamp"])
        if timestamp_text.endswith("Z"):
            timestamp_text = f"{timestamp_text[:-1]}+00:00"

        timestamp = datetime.fromisoformat(timestamp_text)
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)

        status = str(raw["status"]).lower()
        if status not in {"success", "failed"}:
            raise ValueError("status must be either 'success' or 'failed'")

        return cls(
            timestamp=timestamp,
            actor=str(raw["actor"]),
            action=str(raw["action"]),
            status=status,
            source_ip=str(raw["source_ip"]),
        )


def load_events(path: Path | None) -> list[SecurityEvent]:
    """Load events from JSONL, or return built-in demo events."""
    if path is None:
        return [SecurityEvent.from_mapping(item) for item in DEMO_EVENTS]

    events: list[SecurityEvent] = []
    with path.open("r", encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            try:
                raw = json.loads(line)
                if not isinstance(raw, dict):
                    raise ValueError("each line must contain a JSON object")
                events.append(SecurityEvent.from_mapping(raw))
            except (json.JSONDecodeError, ValueError) as error:
                raise ValueError(f"{path}:{line_number}: {error}") from error

    return events


def analyze_events(events: Iterable[SecurityEvent], threshold: int) -> dict[str, Any]:
    """Summarize events and identify repeated authentication failures."""
    event_list = sorted(events, key=lambda event: event.timestamp)
    action_counts = Counter(event.action for event in event_list)
    status_counts = Counter(event.status for event in event_list)
    failed_logins = Counter(
        (event.actor, event.source_ip)
        for event in event_list
        if event.action == "login" and event.status == "failed"
    )

    alerts = [
        {
            "actor": actor,
            "source_ip": source_ip,
            "failed_attempts": attempts,
            "reason": "repeated login failures",
        }
        for (actor, source_ip), attempts in failed_logins.items()
        if attempts >= threshold
    ]

    return {
        "total_events": len(event_list),
        "first_event": event_list[0].timestamp.isoformat() if event_list else None,
        "last_event": event_list[-1].timestamp.isoformat() if event_list else None,
        "actions": dict(action_counts),
        "statuses": dict(status_counts),
        "alerts": alerts,
    }


def print_report(report: dict[str, Any]) -> None:
    """Print a compact human-readable report."""
    print("Security event summary")
    print("=" * 24)
    print(f"Total events : {report['total_events']}")
    print(f"Successful   : {report['statuses'].get('success', 0)}")
    print(f"Failed       : {report['statuses'].get('failed', 0)}")
    print()

    print("Actions")
    for action, count in sorted(report["actions"].items()):
        print(f"  - {action}: {count}")

    print()
    if not report["alerts"]:
        print("Alerts: none")
        return

    print("Alerts")
    for alert in report["alerts"]:
        print(
            "  - "
            f"{alert['actor']} from {alert['source_ip']}: "
            f"{alert['failed_attempts']} failed logins"
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "event_file",
        nargs="?",
        type=Path,
        help="optional UTF-8 JSONL event file",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=3,
        help="failed logins required to create an alert (default: 3)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print the report as JSON",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.threshold < 1:
        raise SystemExit("--threshold must be at least 1")

    try:
        events = load_events(args.event_file)
        report = analyze_events(events, args.threshold)
    except (OSError, ValueError) as error:
        raise SystemExit(f"error: {error}") from error

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print_report(report)

    return 1 if report["alerts"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
