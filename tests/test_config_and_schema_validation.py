from __future__ import annotations

from dataclasses import replace

import pytest
from pydantic import ValidationError

from mimir.config import get_settings, validate_settings
from mimir.schemas import QueryRequest


def test_validate_settings_rejects_short_search_query_max_length():
    settings = replace(get_settings(), search_query_max_length=7)
    with pytest.raises(ValueError, match="SEARCH_QUERY_MAX_LENGTH"):
        validate_settings(settings)


@pytest.mark.parametrize("confidence", [-0.01, 1.01])
def test_validate_settings_rejects_out_of_range_aikg_confidence(confidence: float):
    settings = replace(get_settings(), aikg_import_min_inferred_confidence=confidence)
    with pytest.raises(ValueError, match="AIKG_IMPORT_MIN_INFERRED_CONFIDENCE"):
        validate_settings(settings)


def test_query_request_depth_bounds():
    QueryRequest(depth=0)
    QueryRequest(depth=5)

    with pytest.raises(ValidationError):
        QueryRequest(depth=-1)

    with pytest.raises(ValidationError):
        QueryRequest(depth=6)


def test_cti_source_confidence_rules_map_parses_and_clamps():
    settings = replace(
        get_settings(),
        cti_source_confidence_rules="opencti=0.95,feedly=1.2,bad=oops",
    )
    rules = settings.cti_source_confidence_rules_map
    assert rules["opencti"] == 0.95
    assert rules["feedly"] == 1.0
    assert "bad" not in rules
    assert rules["unknown"] == 0.45


def test_cti_source_confidence_rules_map_uses_defaults_when_empty():
    settings = replace(get_settings(), cti_source_confidence_rules="")
    rules = settings.cti_source_confidence_rules_map
    assert rules["opencti"] == 0.90
    assert rules["unknown"] == 0.45


def test_rss_worker_feeds_list_splits_and_strips():
    settings = replace(
        get_settings(),
        rss_worker_feeds=" https://one.example/rss.xml ,https://two.example/atom.xml ",
    )
    assert settings.rss_worker_feeds_list == [
        "https://one.example/rss.xml",
        "https://two.example/atom.xml",
    ]


def test_validate_settings_rejects_negative_rss_interval():
    settings = replace(get_settings(), rss_worker_interval_minutes=-1)
    with pytest.raises(ValueError, match="RSS_WORKER_INTERVAL_MINUTES"):
        validate_settings(settings)


def test_validate_settings_rejects_unsupported_gvm_connection_type():
    settings = replace(get_settings(), gvm_connection_type="tcp")
    with pytest.raises(ValueError, match="GVM_CONNECTION_TYPE"):
        validate_settings(settings)


def test_validate_settings_rejects_invalid_watcher_timeout():
    settings = replace(get_settings(), watcher_timeout_seconds=0)
    with pytest.raises(ValueError, match="WATCHER_TIMEOUT_SECONDS"):
        validate_settings(settings)
