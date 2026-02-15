# Data Lake Indexes and Taxonomy

This document captures the current Mimir data-lake layout and how worker inputs align to it.
It is structured as:

- What we store
- How data lands in the lake
- Why the model is shaped this way

---

## What We Store

All Mimir-managed Elasticsearch indices are prefixed by `ELASTICSEARCH_INDEX_PREFIX` (default: `mimir`).

| Index | Role | Primary writers |
|---|---|---|
| `{prefix}-runs` | LLM work-queue control plane (`pending`, `running`, `completed`, `failed`, `skipped`) | API ingest/upload/scan, Feedly queue mode, OpenCTI report queue, RSS worker, Elasticsearch worker |
| `{prefix}-documents` | Raw/normalized document payloads for queued runs | `RunStore.create_run()` |
| `{prefix}-chunks` | Chunk materialization per run | LLM worker (`store_chunks`) |
| `{prefix}-entities` | Graph nodes | LLM worker and structured connectors |
| `{prefix}-relations` | Graph edges | LLM worker and structured connectors |
| `{prefix}-provenance` | Evidence snippets tied to extraction/model/timestamp | LLM worker and structured connectors |
| `{prefix}-relation-provenance` | Mapping index between relations and provenance entries | Graph store |
| `{prefix}-metrics` | Daily rollups (`daily_threat_actor`, `daily_pir_entity`, `daily_cti_assessment`) | Metrics rollup |
| `{prefix}-backfill-checkpoints` | Backfill resume checkpoints | Backfill process |

Notes:

- Connector source indices (for example `feedly_news`, `mwdb-openrelik`) are upstream sources, not Mimir lake indices.
- `/api/lake/overview` reports both queued-document coverage (from `{prefix}-documents`) and provenance coverage (from `{prefix}-provenance`), then exposes a combined source view.

---

## How Data Lands In The Lake

### 1. Normalization contract (`metadata.lake`)

Every queued document (`RunStore.create_run`) is normalized through `build_lake_metadata()` into:

- `metadata.lake.version`
- `metadata.lake.source_uri`
- `metadata.lake.source`
- `metadata.lake.collection`
- `metadata.lake.record_id`
- `metadata.lake.ingested_at`

`metadata.source` is also backfilled for compatibility with older consumers.

### 2. Source URI taxonomy rules

`parse_source_uri()` derives `source`, `collection`, and `record_id` from URI scheme/pattern:

| `source_uri` pattern | `source` | `collection` | `record_id` |
|---|---|---|---|
| `opencti://report/<id>` | `opencti` | `report` | `<id>` |
| `opencti://<entity_type>/<id>` | `opencti` | `<entity_type>` normalized to `lower_snake_case` | `<id>` |
| `elasticsearch://<index>/<doc_id>` | `elasticsearch` | `<index>` | `<doc_id>` |
| `malware://<index>/<sample>` | `malware` | `<index>` | `<sample>` |
| `feedly://<canonical_url_or_id>` | `feedly` | `feedly` | `<canonical_url_or_id>` |
| `file://<path>` | `file` | `filesystem` | `<path>` |
| `upload://<name>` | `upload` | `` | `<name>` |
| `stix://<name>` | `stix` | `` | `<name>` |
| `rss://<slug>/<digest>` | `rss` | `<slug>` | `<digest>` |
| `gvm://<host>` | `gvm` | `instance` | `<host>` |
| `watcher://<base_url>` | `watcher` | `instance` | `<base_url>` |

### 3. Two ingestion paths

| Path | Behavior | Destination |
|---|---|---|
| Queue + LLM extraction | Worker/API enqueues run, LLM worker chunks and extracts triples | `{prefix}-runs`, `{prefix}-documents`, `{prefix}-chunks`, graph indices |
| Structured direct import | Connector writes entities/relations/provenance directly | Graph indices (no run/doc entry) |

---

## Worker Input Alignment Review

| Worker/Input path | `source_uri` format | Queued (`runs/documents`)? | Lake taxonomy alignment |
|---|---|---|---|
| Feedly worker (`queue_for_llm=1`) | `feedly://<canonical_url_or_entry_id>` | Yes (optional) | Aligned (`source=feedly`, `collection=feedly`) |
| OpenCTI worker (reports + entity provenance) | `opencti://report/<id>` and `opencti://<entity_type>/<id>` | Yes for reports, direct graph/provenance for entity sync | Aligned (`source=opencti`; `collection` is `report` or normalized OpenCTI entity type) |
| Elasticsearch worker | `elasticsearch://<index>/<doc_id>` | Yes | Aligned (`source=elasticsearch`, `collection=<index>`) |
| RSS worker | `rss://<feed_slug>/<digest>` | Yes | Aligned (`source=rss`, `collection=<feed_slug>`) |
| API `/ingest` | Caller-provided URI | Yes | Depends on caller URI scheme |
| API upload/scan (files) | `upload://<name>` / `file://<path>` | Yes | Aligned for known schemes |
| Malware worker | `malware://<index>/<hash_or_key>` | No (direct graph path) | Source taxonomy consistent, but absent from `{prefix}-documents` |
| GVM worker | `gvm://<host>` | No (direct graph path) | Source taxonomy consistent, but absent from `{prefix}-documents` |
| Watcher worker | `watcher://<base_url>` | No (direct graph path) | Source taxonomy consistent, but absent from `{prefix}-documents` |

Practical implication:

- The `combined_sources` section in `/api/lake/overview` now surfaces graph-only connectors (GVM/Watcher/Malware) through provenance-derived source stats.

---

## Why This Model

- Single normalization envelope (`metadata.lake`) allows cross-source filtering and source-aware rollups without custom per-connector queries.
- Queue-backed ingestion decouples document acquisition from extraction throughput and supports idempotent re-runs.
- Structured connectors can bypass LLM cost/latency where source data is already typed, while still writing provenance-compatible graph data.
- Deterministic IDs in several connectors reduce duplicate queue growth across overlapping lookback windows.

---

## Follow-up Options

1. Add per-source normalization helpers if future URI formats become more complex than the current parser rules.
2. Add pagination/composite aggs in lake overview if your source-uri cardinality can exceed the current aggregation window.
3. Keep worker roster and index inventory synchronized in `docs/architecture.md` when connectors are added.
