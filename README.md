# Mimir

LLM-Native Knowledge Graph (KG) Platform. This repo contains a Python 3.11+ implementation that ingests unstructured text, extracts subject-predicate-object triples with Ollama, normalizes and deduplicates entities, stores a persistent knowledge graph with provenance, and exposes APIs for query, explanation, and visualization.

## Quickstart

1) Start services:

```bash
docker compose up --build
```

2) Ingest text:

```bash
curl -X POST http://localhost:8000/ingest \
  -H 'Content-Type: application/json' \
  -d '{"source_uri": "local://demo", "text": "Ada Lovelace wrote notes on the Analytical Engine."}'
```

3) Query:

```bash
curl -X POST http://localhost:8000/query \
  -H 'Content-Type: application/json' \
  -d '{"seed_name": "Ada Lovelace", "depth": 1}'
```

4) Visualize:

Open `http://localhost:8000/visualize?seed_name=Ada%20Lovelace&depth=1`

## Configuration

Environment variables:
- `OLLAMA_BASE_URL` (default: `http://host.docker.internal:11434`)
- `OLLAMA_MODEL` (default: `llama3.1`)
- `ELASTICSEARCH_HOST` (default: `http://127.0.0.1:9200`, comma-separated for multiple hosts)
- `ELASTICSEARCH_USER` (default: empty)
- `ELASTICSEARCH_PASSWORD` (default: empty)
- `ELASTICSEARCH_INDEX_PREFIX` (default: `mimir`)
- `ELASTICSEARCH_VERIFY_CERTS` (default: `1`)
- `ELASTIC_CONNECTOR_HOSTS` (default: `ELASTICSEARCH_HOST`)
- `ELASTIC_CONNECTOR_USER` (default: `ELASTICSEARCH_USER`)
- `ELASTIC_CONNECTOR_PASSWORD` (default: `ELASTICSEARCH_PASSWORD`)
- `ELASTIC_CONNECTOR_VERIFY_CERTS` (default: `ELASTICSEARCH_VERIFY_CERTS`)
- `ELASTIC_CONNECTOR_ENABLED` (default: `ELASTICSEARCH_ENABLED`, then `true`)
- `ELASTIC_CONNECTOR_TIMEOUT` (default: `ELASTICSEARCH_TIMEOUT`, then `60`)
- `ELASTIC_CONNECTOR_INDICES` (default: `feedly_news`, comma-separated)
- `ELASTIC_CONNECTOR_PAGE_SIZE` (default: `200`)
- `ELASTIC_CONNECTOR_LOOKBACK_MINUTES` (default: `180`)
- `ELASTIC_CONNECTOR_MIN_TEXT_CHARS` (default: `50`)
- `ELASTIC_CONNECTOR_STRIP_HTML` (default: `1`)
- `ELASTIC_CONNECTOR_NORMALIZE_WHITESPACE` (default: `1`)
- `ELASTIC_CONNECTOR_TITLE_FIELDS` (default: `title,headline,name`)
- `ELASTIC_CONNECTOR_TEXT_FIELDS` (default: `content,text,summary,description,body,full_text`)
- `ELASTIC_CONNECTOR_URL_FIELDS` (default: `url,link,origin_url`)
- `ELASTIC_CONNECTOR_TIMESTAMP_FIELDS` (default: `@timestamp,published,published_at,updated_at,created_at,timestamp`)
- `ELASTICSEARCH_URL` (alias for connector host)
- `ELASTICSEARCH_INDEX` (alias for connector indices)
- `ELASTICSEARCH_USERNAME` (alias for connector user)
- `ELASTICSEARCH_VERIFY_TLS` (alias for connector TLS verification)
- `ELASTICSEARCH_TIMEOUT` (alias for connector timeout)
- `ELASTICSEARCH_BATCH_SIZE` (alias for connector page size)
- `CHUNK_SIZE` (default: `1200`)
- `CHUNK_OVERLAP` (default: `200`)
- `PROMPT_VERSION` (default: `v1`)
- `LOG_LEVEL` (default: `INFO`)
- `MIMIR_API_BASE_URL` (default: empty; optional absolute API base URL for UI fetches)
  - Backward compatible fallback: `WELLSPRING_API_BASE_URL`
- `QUERY_MAX_NODES` (default: `400`; soft cap for `/query` and `/visualize`, `0` disables)
- `QUERY_MAX_EDGES` (default: `1200`; soft cap for `/query` and `/visualize`, `0` disables)
- `ENABLE_COOCCURRENCE` (default: `0`)
- `CO_OCCURRENCE_MAX_ENTITIES` (default: `25`)
- `ENABLE_INFERENCE` (default: `0`)
- `METRICS_ROLLUP_ENABLED` (default: `1`)
- `METRICS_ROLLUP_INTERVAL_SECONDS` (default: `900`)
- `METRICS_ROLLUP_LOOKBACK_DAYS` (default: `365`)
- `METRICS_ROLLUP_MIN_CONFIDENCE` (default: `0.0`)
- `METRICS_ROLLUP_STALE_SECONDS` (default: `0` = auto threshold)
- `CTI_ROLLUP_ENABLED` (default: `1`)
- `CTI_ROLLUP_LOOKBACK_DAYS` (default: `365`)
- `CTI_DECAY_HALF_LIFE_DAYS` (default: `14`)
- `CTI_LEVEL_THRESHOLDS` (default: `0.2,0.4,0.6,0.8`)

Inference (when enabled) currently applies a simple transitive rule for `is_a` relations within a chunk.

### Elasticsearch backend example

```bash
export ELASTICSEARCH_HOST=http://192.168.2.50:9200
export ELASTICSEARCH_USER=elastic
export ELASTICSEARCH_PASSWORD='your-password'
```

### Elasticsearch source connector

Pull docs from external/source Elasticsearch indices into Mimir's run queue:

```bash
curl -X POST "http://localhost:8000/api/elasticsearch/pull"
```

This manual pull endpoint works even if `ELASTICSEARCH_ENABLED=false` in `.env`.

By default this pulls the configured `ELASTIC_CONNECTOR_INDICES` list (initially
`feedly_news`) and queues new/updated docs for LLM extraction.

Before queueing, the connector aligns source records into canonical `title/text/url`
fields and applies optional text normalization (HTML stripping + whitespace cleanup).

To override indices and window per run:

```bash
curl -X POST "http://localhost:8000/api/elasticsearch/pull?indices=feedly_news&max_per_index=1000&lookback_minutes=120"
```

## Temporal Analysis

Use `since` / `until` on `/query` to filter graph edges by provenance timestamp.
`/query` responses are capped by `QUERY_MAX_NODES` / `QUERY_MAX_EDGES` by default to keep the UI responsive. You can override per request with `max_nodes` and `max_edges`.

```bash
curl -X POST http://localhost:8000/query \
  -H 'Content-Type: application/json' \
  -d '{
    "seed_name": "APT28",
    "depth": 2,
    "since": "2025-01-01T00:00:00Z",
    "until": "2025-12-31T23:59:59Z"
  }'
```

Use `/api/timeline/entity` to see how an entity changes over time:

```bash
curl "http://localhost:8000/api/timeline/entity?entity_name=APT28&interval=month&depth=2"
```

Use `/api/timeline/threat-actors` to compare threat-actor activity over time
(global or scoped around a seed entity):

```bash
curl "http://localhost:8000/api/timeline/threat-actors?interval=month&top_n=10&since=2025-01-01T00:00:00Z"
```

Daily threat-actor metrics are rolled up into the Elasticsearch index
`<ELASTICSEARCH_INDEX_PREFIX>-metrics` (default: `mimir-metrics`).
The worker updates this on a schedule, and `/api/stats` exposes freshness and
active-actor counts for the last 30 days.
PIR trend summaries are also precomputed daily in this metrics index and served
by `/api/pir/trending`, avoiding heavy on-demand provenance scans.
CTI assessment summaries are also precomputed daily and served by:

- `/api/cti/overview`
- `/api/cti/trends`

You can also trigger a manual rollup (threat actors + PIR + CTI):

```bash
curl -X POST "http://localhost:8000/api/metrics/rollup?lookback_days=365&min_confidence=0.2"
```

Skip CTI in manual rollup when needed:

```bash
curl -X POST "http://localhost:8000/api/metrics/rollup?include_cti=false"
```

Query CTI summaries:

```bash
curl "http://localhost:8000/api/cti/overview?days=30"
curl "http://localhost:8000/api/cti/trends?days=30&group_by=activity&top_n=10"
```

Optionally scope rollups and stats to a source URI:

```bash
curl -X POST "http://localhost:8000/api/metrics/rollup?source_uri=elasticsearch://feedly_news/doc-123"
curl "http://localhost:8000/api/stats?source_uri=elasticsearch://feedly_news/doc-123"
```

Data quality summary (coverage, orphan relations, missing timestamps):

```bash
curl "http://localhost:8000/api/data-quality?days=30"
```

In the web UI, use the `Since`, `Until`, and `Timeline interval` controls in Explore, then click `Visualize` to render both the filtered graph and timeline panel.
