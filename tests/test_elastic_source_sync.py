from wellspring.elastic_source.sync import (
    _align_document,
    _build_document_text,
    _build_run_id,
    _build_version_token,
    _select_timestamp_field,
)


def test_build_document_text_prefers_configured_title_and_text_fields():
    source = {
        "title": "Feedly headline",
        "content": "Primary body text",
        "summary": "Primary body text",
    }
    title, text = _build_document_text(
        source,
        title_fields=["title", "headline"],
        text_fields=["content", "summary"],
        strip_html=True,
        normalize_whitespace=True,
    )
    assert title == "Feedly headline"
    assert text == "Feedly headline\n\nPrimary body text"


def test_build_document_text_falls_back_to_scalar_fields():
    source = {"headline": "Alert", "url": "https://example.com/a"}
    title, text = _build_document_text(
        source,
        title_fields=["title"],
        text_fields=["content"],
        strip_html=True,
        normalize_whitespace=True,
    )
    assert title == ""
    assert "headline: Alert" in text
    assert "url: https://example.com/a" in text


def test_select_timestamp_field_uses_first_date_candidate():
    field_types = {
        "published_at": "date",
        "title": "text",
        "updated_at": "keyword",
    }
    selected = _select_timestamp_field(
        field_types,
        candidates=["updated_at", "published_at", "@timestamp"],
    )
    assert selected == "published_at"


def test_select_timestamp_field_falls_back_to_existing_non_date_field():
    field_types = {
        "published_at": "keyword",
        "title": "text",
    }
    selected = _select_timestamp_field(
        field_types,
        candidates=["updated_at", "published_at", "@timestamp"],
    )
    assert selected == "published_at"


def test_build_version_token_prefers_seq_no_when_timestamp_missing():
    token = _build_version_token(
        {"_seq_no": 17, "_primary_term": 4},
        timestamp_value=None,
        text="body",
    )
    assert token == "seq:17:4"


def test_build_version_token_includes_timestamp_and_seq_when_both_present():
    token = _build_version_token(
        {"_seq_no": 18, "_primary_term": 4},
        timestamp_value="2026-02-12T10:30:00Z",
        text="body",
    )
    assert token == "ts:2026-02-12T10:30:00Z|seq:18:4"


def test_build_run_id_is_stable_and_versioned():
    run_a = _build_run_id("feedly_news", "doc-1", "ts:2026-02-12T10:00:00Z")
    run_b = _build_run_id("feedly_news", "doc-1", "ts:2026-02-12T10:00:00Z")
    run_c = _build_run_id("feedly_news", "doc-1", "ts:2026-02-12T10:30:00Z")
    assert run_a == run_b
    assert run_a != run_c


def test_align_document_strips_html_and_normalizes():
    source = {
        "headline": "<b>APT Update</b>",
        "content": "<p>Actor&nbsp;used <i>phishing</i>.</p>",
        "url": "https://example.com/post",
        "@timestamp": "2026-02-12T10:30:00Z",
    }
    aligned = _align_document(
        source,
        title_fields=["headline"],
        text_fields=["content"],
        url_fields=["url"],
        timestamp_field="@timestamp",
        strip_html=True,
        normalize_whitespace=True,
    )
    assert aligned["title"] == "APT Update"
    assert aligned["text"] == "APT Update\n\nActor used phishing."
    assert aligned["url"] == "https://example.com/post"
    assert aligned["timestamp_value"] == "2026-02-12T10:30:00Z"
