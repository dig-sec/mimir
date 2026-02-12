from datetime import datetime, timezone

from wellspring.pipeline.runner import _resolve_provenance_timestamp


def test_resolve_provenance_timestamp_prefers_metadata_timestamp_value():
    ts = _resolve_provenance_timestamp({"timestamp_value": "2026-02-12T10:30:00Z"})
    assert ts.isoformat().startswith("2026-02-12T10:30:00")


def test_resolve_provenance_timestamp_supports_epoch_millis():
    ts = _resolve_provenance_timestamp({"timestamp": 1_707_735_000_000})
    assert isinstance(ts, datetime)
    assert ts.year >= 2024
    assert ts.tzinfo == timezone.utc


def test_resolve_provenance_timestamp_supports_epoch_millis_string():
    ts = _resolve_provenance_timestamp({"timestamp_value": "1707735000000"})
    assert isinstance(ts, datetime)
    assert ts.year >= 2024
    assert ts.tzinfo == timezone.utc


def test_resolve_provenance_timestamp_normalizes_naive_iso_to_utc():
    ts = _resolve_provenance_timestamp({"published_at": "2026-02-12T10:30:00"})
    assert ts.tzinfo == timezone.utc
    assert ts.isoformat().startswith("2026-02-12T10:30:00+00:00")


def test_resolve_provenance_timestamp_fallbacks_to_now():
    ts = _resolve_provenance_timestamp({})
    assert isinstance(ts, datetime)
    assert ts.tzinfo == timezone.utc
