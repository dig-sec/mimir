from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import httpx

from mimir.config import get_settings
from mimir.connectors.rss import _build_run_id, _parse_feed_entries, pull_from_rss_feeds


class _DummyRunStore:
    def __init__(self) -> None:
        self.existing: set[str] = set()
        self.created: list[dict] = []

    def get_run(self, run_id: str):
        if run_id in self.existing:
            return {"run_id": run_id}
        return None

    def create_run(self, run, source_uri: str, text: str, metadata=None):
        self.existing.add(run.run_id)
        self.created.append(
            {
                "run_id": run.run_id,
                "source_uri": source_uri,
                "text": text,
                "metadata": metadata or {},
            }
        )


def test_parse_feed_entries_supports_rss_and_atom():
    rss_xml = """
    <rss version="2.0">
      <channel>
        <title>Example RSS</title>
        <item>
          <title>Alert One</title>
          <link>https://example.com/a1</link>
          <guid>guid-1</guid>
          <pubDate>Mon, 01 Jan 2026 12:00:00 GMT</pubDate>
          <description>Important update</description>
        </item>
      </channel>
    </rss>
    """
    atom_xml = """
    <feed xmlns="http://www.w3.org/2005/Atom">
      <title>Example Atom</title>
      <entry>
        <id>atom-1</id>
        <title>Atom Alert</title>
        <updated>2026-01-01T12:00:00Z</updated>
        <link href="https://example.com/atom-1" rel="alternate" />
        <summary>Atom summary</summary>
      </entry>
    </feed>
    """

    rss_title, rss_entries = _parse_feed_entries(rss_xml)
    atom_title, atom_entries = _parse_feed_entries(atom_xml)

    assert rss_title == "Example RSS"
    assert rss_entries[0]["guid"] == "guid-1"
    assert rss_entries[0]["link"] == "https://example.com/a1"

    assert atom_title == "Example Atom"
    assert atom_entries[0]["guid"] == "atom-1"
    assert atom_entries[0]["link"] == "https://example.com/atom-1"


def test_pull_from_rss_feeds_queues_only_new_recent_items():
    now = datetime.now(timezone.utc)
    recent = now.strftime("%a, %d %b %Y %H:%M:%S GMT")
    old = (now - timedelta(days=10)).strftime("%a, %d %b %Y %H:%M:%S GMT")
    feed_url = "https://feeds.example.local/alerts.xml"
    feed_xml = f"""
    <rss version="2.0">
      <channel>
        <title>Security Alerts</title>
        <item>
          <title>Existing Item</title>
          <guid>guid-existing</guid>
          <link>https://example.local/existing</link>
          <pubDate>{recent}</pubDate>
          <description>Existing summary text</description>
        </item>
        <item>
          <title>New Item</title>
          <guid>guid-new</guid>
          <link>https://example.local/new</link>
          <pubDate>{recent}</pubDate>
          <description>New summary text that should be queued</description>
        </item>
        <item>
          <title>Old Item</title>
          <guid>guid-old</guid>
          <link>https://example.local/old</link>
          <pubDate>{old}</pubDate>
          <description>Old summary text</description>
        </item>
      </channel>
    </rss>
    """
    store = _DummyRunStore()
    store.existing.add(_build_run_id(feed_url, "guid-existing"))

    settings = replace(get_settings())

    def _fake_fetch(_client: httpx.Client, url: str) -> str:
        assert url == feed_url
        return feed_xml

    result = pull_from_rss_feeds(
        store,
        settings,
        [feed_url],
        lookback_hours=24,
        max_items_per_feed=100,
        min_text_chars=20,
        timeout_seconds=5,
        fetch_feed=_fake_fetch,
    )

    assert result.feeds_scanned == 1
    assert result.items_seen == 3
    assert result.runs_queued == 1
    assert result.skipped_existing == 1
    assert result.skipped_old == 1
    assert len(store.created) == 1
    assert store.created[0]["metadata"]["connector"] == "rss"
