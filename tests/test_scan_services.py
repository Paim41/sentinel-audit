from datetime import datetime, timezone

from app.scans.services import _duration_seconds


def test_duration_seconds_handles_naive_started_at_and_aware_completed_at():
    started_at = datetime(2026, 7, 4, 1, 0, 0)
    completed_at = datetime(2026, 7, 4, 1, 0, 3, 500000, tzinfo=timezone.utc)

    assert _duration_seconds(started_at, completed_at) == 3.5
