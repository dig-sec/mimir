# Mimir Architecture

Mimir is an LLM-powered **cyber-threat intelligence knowledge-graph** platform.
It ingests structured and unstructured data from multiple sources, extracts
entities and relationships using a local LLM, and stores everything in an
Elasticsearch-backed graph with full provenance tracking.

---

## High-Level Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                          Data Sources                               │
│  ┌──────────┐   ┌──────────────┐   ┌───────────────────────────┐   │
│  │  Feedly   │   │   OpenCTI    │   │  Elasticsearch Indices    │   │
│  │  (via ES) │   │  (GraphQL)   │   │  (generic doc sources)    │   │
│  └─────┬─────┘   └──────┬───────┘   └────────────┬──────────────┘   │
└────────┼────────────────┼────────────────────────┼──────────────────┘
         │                │                        │
         ▼                ▼                        ▼
┌─────────────┐  ┌────────────────┐  ┌──────────────────┐
│ feedly-     │  │ opencti-       │  │ elastic-         │
│ worker      │  │ worker         │  │ worker           │
│ (connector) │  │ (connector)    │  │ (connector)      │
└──────┬──────┘  └───────┬────────┘  └────────┬─────────┘
       │                 │                     │
       │    Structured   │   Entities +        │  Queue documents
       │    graph data   │   Relations         │  for LLM
       │    + queue text │                     │
       ▼                 ▼                     ▼
┌──────────────────────────────────────────────────────┐
│                   Elasticsearch                       │
│                                                       │
│  ┌────────────┐ ┌──────────┐ ┌────────────────────┐  │
│  │  Entities  │ │Relations │ │  RunStore (Queue)   │  │
│  │  Index     │ │ Index    │ │  pending → running  │  │
│  └────────────┘ └──────────┘ │  → completed/failed │  │
│  ┌────────────┐ ┌──────────┐ └────────────────────┘  │
│  │ Provenance │ │ Metrics  │                          │
│  │  Index     │ │ Index    │                          │
│  └────────────┘ └──────────┘                          │
└──────────────────────┬───────────────────────────────┘
                       │
                       │  claim_next_run()
                       ▼
              ┌─────────────────┐
              │   llm-worker    │
              │                 │
              │  ┌───────────┐  │
              │  │ Semaphore │  │   N concurrent
              │  │ (N=3)    │  │   extractions
              │  └───────────┘  │
              │       │         │
              │       ▼         │
              │  ┌──────────┐   │
              │  │  Ollama   │  │
              │  │  (LLM)   │  │
              │  └──────────┘   │
              └────────┬────────┘
                       │
                       │  upsert entities/relations
                       ▼
              ┌─────────────────┐
              │   FastAPI (API) │
              │                 │
              │  Web UI + REST  │
              │  MCP Server     │
              │  STIX Export    │
              └─────────────────┘
```

---

## Process Architecture

Mimir runs as **six independent processes**, all built from the same
Docker image with different `command` overrides:

| Service | Module | Purpose |
|---------|--------|---------|
| **api** | `mimir.api.app` (uvicorn) | FastAPI web server — UI, REST API, export |
| **llm-worker** | `mimir.worker.llm_worker` | Consumes run queue, processes text through LLM |
| **feedly-worker** | `mimir.worker.feedly_worker` | Periodic Feedly article sync from Elasticsearch |
| **opencti-worker** | `mimir.worker.opencti_worker` | Periodic entity/relation sync from OpenCTI |
| **elastic-worker** | `mimir.worker.elastic_worker` | Periodic document pull from ES source indices |
| **backfill** | `mimir.backfill` | One-shot historical data backfill (on-demand) |

### Why separate processes?

Previously, the API process ran an inline scheduler for connector syncs,
and a single monolithic worker sequentially processed LLM extractions.
This created two problems:

1. **LLM bottleneck** — chunks were processed one at a time through the LLM
2. **Coupled lifecycle** — connector syncs shared the API process, and a
   connector failure could impact API availability

The current architecture solves both:

- The **LLM worker** uses an `asyncio.Semaphore` to process multiple runs
  concurrently (`LLM_WORKER_CONCURRENCY`, default 3) and can also be
  **scaled horizontally** (`docker compose up --scale llm-worker=3`)
- Each **connector worker** runs independently with its own schedule and
  failure domain

---

## Module Map

```
src/mimir/
├── __init__.py
│
├── config.py              # Settings dataclass — all env-var driven
├── schemas.py             # Pydantic models: Entity, Relation, Provenance, etc.
├── normalize.py           # Entity name + predicate normalization
├── dedupe.py              # EntityResolver — deterministic dedup via canonical keys
├── chunking.py            # Text → Chunk splitting with overlap
├── export.py              # CSV, GraphML, JSON, Markdown export helpers
├── backfill.py            # Historical backfill with checkpoint resumption
│
├── api/                   # FastAPI application
│   ├── app.py             # App factory + lifespan
│   ├── routes.py          # All REST + HTML endpoints
│   ├── scheduler.py       # (Legacy) inline sync scheduler — no longer used
│   ├── tasks.py           # In-memory background task manager
│   ├── ui.py              # Jinja2 HTML template rendering
│   ├── visualize.py       # Graph visualization helpers
│   └── static/            # Frontend JS + CSS
│       ├── main.js        # App entrypoint, tab management
│       ├── graph.js       # D3.js force-directed graph visualization
│       ├── sidebar.js     # Entity detail sidebar
│       ├── pir.js         # Priority Intelligence Requirements
│       ├── ingest.js      # Document upload / ingest UI
│       ├── opencti.js     # OpenCTI sync UI
│       ├── helpers.js     # Shared JS utilities
│       └── style.css      # Stylesheet
│
├── connectors/
│   └── __init__.py        # Feedly connector — Feedly-AI entity extraction
│
├── elastic_source/
│   ├── client.py          # ElasticsearchSourceClient (search_after pagination)
│   └── sync.py            # pull_from_elasticsearch() — doc→queue pipeline
│
├── llm/
│   ├── ollama.py          # Async OllamaClient (httpx)
│   ├── parse.py           # JSON extraction from LLM output
│   ├── prompts.py         # Jinja2 prompt rendering
│   └── prompts/
│       └── extract_triples.jinja2   # Triple extraction prompt template
│
├── mcp/
│   └── server.py          # MCP server for VS Code Copilot integration
│
├── opencti/
│   ├── client.py          # OpenCTI GraphQL client (paginated)
│   └── sync.py            # pull_from_opencti() — entity/relation/report sync
│
├── pipeline/
│   └── runner.py          # process_run() — chunk text → LLM → graph upsert
│
├── stix/
│   ├── exporter.py        # Mimir graph → STIX 2.1 bundles
│   └── importer.py        # STIX 2.1 bundles → Mimir graph
│
├── storage/
│   ├── base.py            # Abstract GraphStore interface
│   ├── run_store.py       # Abstract RunStore interface (work queue)
│   ├── metrics_store.py   # Abstract MetricsStore interface
│   ├── elastic_store.py   # Elasticsearch implementations of all stores
│   ├── factory.py         # Store factory (settings → concrete store)
│   └── sqlite_store.py    # SQLite store (development / testing)
│
└── worker/
    ├── main.py            # Legacy entrypoint — delegates to llm_worker
    ├── connector_worker_template.py  # Template skeleton for new connector workers
    ├── llm_worker.py      # LLM extraction worker (concurrent queue consumer)
    ├── feedly_worker.py   # Feedly connector worker (periodic sync)
    ├── opencti_worker.py  # OpenCTI connector worker (periodic sync)
    └── elastic_worker.py  # Elasticsearch source worker (periodic sync)
```

---

## Data Flow

### 1. Ingestion (Connector Workers)

Each connector worker runs on a configurable interval and pulls data from
its respective source:

#### Feedly Worker (`feedly_worker.py`)
```
Elasticsearch (feedly_news index)
  → Feedly connector (connectors/__init__.py)
    → Parses Feedly-AI entities, IOCs, topics
    → Upserts structured graph data (entities + relations) directly
    → Optionally queues article text for LLM extraction (FEEDLY_QUEUE_FOR_LLM=1)
```

#### OpenCTI Worker (`opencti_worker.py`)
```
OpenCTI (GraphQL API)
  → OpenCTI sync (opencti/sync.py)
    → Pulls entities by type (malware, threat actors, etc.)
    → Pulls relationships between entities
    → Pulls reports → queues report text for LLM extraction
    → Upserts all to graph store
```

#### Elasticsearch Worker (`elastic_worker.py`)
```
Elasticsearch (configurable source indices)
  → ES sync (elastic_source/sync.py)
    → Extracts text from documents (configurable field mapping)
    → Normalizes text (strip HTML, whitespace)
    → Queues for LLM extraction via RunStore.create_run()
```

### 2. LLM Extraction (LLM Worker)

```
RunStore (pending runs)
  → llm_worker claims run via claim_next_run()
    → Loads document text from RunStore
    → Splits into chunks (chunking.py)
    → For each chunk (up to N concurrent):
        → Renders Jinja2 prompt (llm/prompts.py)
        → Sends to Ollama LLM (llm/ollama.py)
        → Parses JSON triples from response (llm/parse.py)
        → Resolves entities via EntityResolver (dedupe.py)
        → Normalizes predicates (normalize.py)
        → Upserts entities + relations + provenance to graph store
    → Marks run as completed/failed
```

### 3. Querying (API)

```
User (Web UI / REST API / MCP)
  → FastAPI routes
    → GraphStore.search_entities()     — full-text entity search
    → GraphStore.get_subgraph()        — neighborhood traversal
    → GraphStore.explain_edge()        — relation provenance
    → Export as STIX / CSV / GraphML / JSON / Markdown
```

---

## Storage Layer

All persistence is in **Elasticsearch** with indices prefixed by
`ELASTICSEARCH_INDEX_PREFIX` (default `mimir`):

| Index | Contents |
|-------|----------|
| `{prefix}-entities` | Entity documents (name, type, aliases, attrs) |
| `{prefix}-relations` | Relation documents (subject, predicate, object, confidence) |
| `{prefix}-provenance` | Provenance records linking relations to source text snippets |
| `{prefix}-runs` | Extraction run queue (status: pending/running/completed/failed) |
| `{prefix}-chunks` | Text chunks for completed extraction runs |
| `{prefix}-metrics-*` | Rollup metrics (threat actor daily stats) |
| `{prefix}-backfill-checkpoints` | Backfill progress checkpoints |

### RunStore as Work Queue

The `RunStore` serves as the work queue between connector workers and the
LLM worker, using Elasticsearch's optimistic concurrency control:

```
create_run()        → Connector creates a run with status "pending"
claim_next_run()    → LLM worker atomically sets status to "running"
update_run_status() → Worker sets "completed" or "failed"
recover_stale_runs()→ On startup, resets "running" → "pending" (crash recovery)
```

This eliminates the need for a separate message broker (Redis, RabbitMQ).

---

## Entity Resolution & Deduplication

The `EntityResolver` in `dedupe.py` ensures the same real-world entity
maps to one graph node:

1. **Normalize** the entity name (strip whitespace, collapse spaces)
2. Compute a **canonical key** = `lowercase_normalized_name|entity_type`
3. Generate a **deterministic UUID5** from the canonical key
4. **Search** the graph store for existing entities with matching canonical key
5. If found → return existing entity; otherwise → create and upsert new entity

This means "APT28", "apt28", and " APT28 " all resolve to the same entity.

---

## LLM Pipeline Detail

The extraction pipeline in `pipeline/runner.py`:

1. **Chunking** — Split document text into overlapping windows
   (`CHUNK_SIZE=1200`, `CHUNK_OVERLAP=200`)
2. **Prompt rendering** — Jinja2 template (`extract_triples.jinja2`)
   instructs the LLM to output structured JSON triples
3. **LLM call** — Async HTTP to Ollama (`/api/generate`, no streaming)
4. **Response parsing** — Extract JSON from LLM output, tolerating
   markdown fences, partial JSON, etc.
5. **Entity resolution** — Each subject/object is resolved via `EntityResolver`
6. **Predicate normalization** — `normalize_predicate()` lowercases and
   snake_cases relationship types
7. **Graph upsert** — Entities, relations, and provenance records are
   upserted to Elasticsearch
8. **Provenance** — Every relation is linked to the exact source snippet,
   extraction model, and timestamp

---

## API Endpoints

### Web UI
| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Main web UI (graph + sidebar + PIR) |
| GET | `/visualize` | Full-page graph visualization |

### Search & Query
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/search` | Full-text entity search |
| POST | `/query` | Subgraph query by seed entity |
| GET | `/explain` | Relation/entity provenance |

### Ingestion
| Method | Path | Description |
|--------|------|-------------|
| POST | `/ingest` | Submit text for LLM extraction |
| POST | `/api/upload` | File upload for extraction |
| POST | `/api/scan` | Scan watched folders |

### Data Source Management
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/feedly/pull` | Manual Feedly sync |
| POST | `/api/opencti/pull` | Manual OpenCTI sync |
| POST | `/api/elasticsearch/pull` | Manual Elasticsearch sync |
| POST | `/api/sources/pull-all` | Trigger all sources |
| POST | `/api/backfill` | Start historical backfill |
| GET | `/api/backfill/status` | Backfill progress |

### Export
| Method | Path | Description |
|--------|------|-------------|
| GET/POST | `/api/export/stix` | STIX 2.1 bundle |
| GET/POST | `/api/export/csv` | CSV zip (entities + relations) |
| GET/POST | `/api/export/graphml` | GraphML for Gephi / yEd |
| GET/POST | `/api/export/json` | Raw JSON |
| GET/POST | `/api/export/markdown` | Markdown report |

### Operational
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/runs` | List extraction runs |
| GET | `/runs/{run_id}` | Run status |
| DELETE | `/api/runs` | Delete all runs |
| POST | `/api/recover-stale-runs` | Reset stale runs |
| GET | `/api/stats` | Graph statistics |
| GET | `/api/data-quality` | Data quality metrics |
| GET | `/api/tasks` | Background task list |
| POST | `/api/metrics/rollup` | Trigger metrics rollup |

### Intelligence
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/timeline/entity` | Entity event timeline |
| GET | `/api/timeline/threat-actors` | Threat actor activity timeline |
| GET | `/api/pir/trending` | Trending entities for PIR |
| GET | `/api/pir/entity-context` | Entity context for PIR analysis |

---

## MCP Server (VS Code Integration)

The MCP server (`mcp/server.py`) exposes graph query tools to VS Code
Copilot via the **Model Context Protocol**, enabling natural-language
intelligence queries directly from the IDE.

Tools exposed:
- `search_entities` — Search entities by name and/or type
- `get_entity` — Get entity by ID
- `get_subgraph` — Neighborhood traversal around an entity
- `explain_entity` — Entity details with relations and provenance
- `explain_relation` — Relation provenance and extraction run info
- `graph_stats` — High-level graph statistics
- `list_recent_runs` — Recent extraction run status

Configuration is in `.vscode/mcp.json` for workspace-level integration.

---

## STIX 2.1 Integration

Mimir supports bidirectional STIX 2.1 exchange:

- **Export** (`stix/exporter.py`) — Converts graph subsets to valid STIX bundles
  with proper SDO/SRO type mapping. Usable for TAXII feeds, MISP, OpenCTI import.
- **Import** (`stix/importer.py`) — Parses STIX bundles into Mimir entities
  and relations, bypassing LLM extraction for already-structured data.

---

## Configuration Reference

All configuration is via environment variables, read at startup by the
`Settings` dataclass in `config.py`.

### Core
| Variable | Default | Description |
|----------|---------|-------------|
| `ELASTICSEARCH_HOST` | `http://127.0.0.1:9200` | Elasticsearch cluster URL |
| `ELASTICSEARCH_USER` | _(empty)_ | Elasticsearch username |
| `ELASTICSEARCH_PASSWORD` | _(empty)_ | Elasticsearch password |
| `ELASTICSEARCH_INDEX_PREFIX` | `mimir` | Index name prefix |
| `ELASTICSEARCH_VERIFY_CERTS` | `1` | TLS certificate verification |
| `LOG_LEVEL` | `INFO` | Python logging level |

### LLM
| Variable | Default | Description |
|----------|---------|-------------|
| `OLLAMA_BASE_URL` | `http://host.docker.internal:11434` | Ollama API base URL |
| `OLLAMA_MODEL` | `phi4` | LLM model name |
| `PROMPT_VERSION` | `v1` | Prompt template version |
| `CHUNK_SIZE` | `1200` | Characters per text chunk |
| `CHUNK_OVERLAP` | `200` | Overlap between chunks |
| `MAX_CHUNKS_PER_RUN` | `50` | Maximum chunks per extraction run |

### LLM Worker
| Variable | Default | Description |
|----------|---------|-------------|
| `LLM_WORKER_CONCURRENCY` | `3` | Concurrent extraction tasks per worker |
| `LLM_WORKER_POLL_SECONDS` | `2` | Queue poll interval |

### Feedly Connector Worker
| Variable | Default | Description |
|----------|---------|-------------|
| `ELASTIC_CONNECTOR_ENABLED` | `1` | Enable Feedly connector |
| `ELASTIC_CONNECTOR_HOSTS` | _(from ELASTICSEARCH_HOST)_ | Feedly ES cluster |
| `ELASTIC_CONNECTOR_INDICES` | `feedly_news` | Comma-separated index names |
| `ELASTIC_CONNECTOR_LOOKBACK_MINUTES` | `180` | How far back to search |
| `FEEDLY_WORKER_INTERVAL_MINUTES` | `30` | Sync interval |
| `FEEDLY_QUEUE_FOR_LLM` | `0` | Queue article text for LLM extraction |

### OpenCTI Connector Worker
| Variable | Default | Description |
|----------|---------|-------------|
| `OPENCTI_URL` | _(empty)_ | OpenCTI instance URL |
| `OPENCTI_TOKEN` | _(empty)_ | OpenCTI API token |
| `OPENCTI_WORKER_INTERVAL_MINUTES` | `30` | Sync interval |

### Elasticsearch Source Worker
| Variable | Default | Description |
|----------|---------|-------------|
| `ELASTIC_WORKER_INTERVAL_MINUTES` | `30` | Sync interval |
| `ELASTIC_CONNECTOR_TEXT_FIELDS` | `content,text,summary,...` | Fields to extract text from |
| `ELASTIC_CONNECTOR_MIN_TEXT_CHARS` | `50` | Minimum text length to process |

### General Sync
| Variable | Default | Description |
|----------|---------|-------------|
| `SYNC_INTERVAL_MINUTES` | `30` | Default interval (fallback for workers) |
| `SYNC_LOOKBACK_MINUTES` | `60` | Lookback window for connector syncs |

### Metrics
| Variable | Default | Description |
|----------|---------|-------------|
| `METRICS_ROLLUP_ENABLED` | `1` | Enable periodic metrics rollup |
| `METRICS_ROLLUP_INTERVAL_SECONDS` | `900` | Rollup interval (15 min) |
| `METRICS_ROLLUP_LOOKBACK_DAYS` | `365` | How far back to aggregate |

### Features
| Variable | Default | Description |
|----------|---------|-------------|
| `ENABLE_COOCCURRENCE` | `0` | Enable co-occurrence relation extraction |
| `ENABLE_INFERENCE` | `0` | Enable inference-based relation creation |

---

## Deployment

### Docker Compose (Production)

```bash
# Start all services
docker compose up -d

# Scale LLM workers for higher throughput
docker compose up -d --scale llm-worker=3

# Run historical backfill (one-shot)
docker compose run --rm backfill

# View logs for a specific worker
docker compose logs -f llm-worker
docker compose logs -f feedly-worker
```

### Local Development

```bash
# Install in development mode
pip install -e ".[dev]"

# Run the API
uvicorn mimir.api.app:app --reload --port 8000

# Run individual workers
python -m mimir.worker.llm_worker
python -m mimir.worker.feedly_worker
python -m mimir.worker.opencti_worker
python -m mimir.worker.elastic_worker
```

### Scaling Considerations

- **LLM workers** are the primary scaling lever. Each worker instance
  processes `LLM_WORKER_CONCURRENCY` runs in parallel. Multiple worker
  replicas safely compete for runs via the RunStore's atomic claim mechanism.
- **Connector workers** should run as single instances — they are
  idempotent but running duplicates wastes resources.
- **Ollama** is the true bottleneck. Running it on a GPU with sufficient
  VRAM is critical. Multiple LLM worker replicas share the same Ollama
  instance — Ollama handles request queuing internally.

---

## Default Connector Worker Template

Use this pattern when adding new source connectors.

### Template goals

1. Keep connector sync isolated from API process failures
2. Support graceful shutdown on `SIGINT` / `SIGTERM`
3. Keep sync idempotent across overlapping windows
4. Run blocking source-client code in `asyncio.to_thread(...)`
5. Emit clear per-cycle logs and progress metrics

### Expected lifecycle

1. Load settings and initialize logging
2. Validate connector prerequisites (enabled flags, credentials, hosts)
3. Build stores (`create_graph_store`, `create_run_store` as needed)
4. Register signal handlers
5. Loop:
   - compute `cycle_end` + lookback-based `cycle_start`
   - run one sync cycle (`asyncio.to_thread`)
   - log summary and partial errors
   - wait for next interval or shutdown event
6. Exit cleanly when shutdown is requested

### Source template

Copy from:

- `src/mimir/worker/connector_worker_template.py`

Recommended copy flow:

1. Copy template to `src/mimir/worker/<name>_worker.py`
2. Replace `_run_sync_once(...)` with your connector call
3. Add connector-specific config fields to `config.py`
4. Add service to `docker-compose.yml`
5. Document env vars in this architecture doc and `README.md`

### Implementation checklist

- Idempotency: dedupe by source URI / external ID / version token
- Windowing: use lookback windows to handle delayed arrivals
- Back-pressure: avoid unbounded queue growth
- Observability: log docs seen, entities/relations upserted, queued runs, errors
- Failure handling: continue after per-cycle failures; do not crash-loop

---

## Technology Stack

| Component | Technology |
|-----------|------------|
| Language | Python 3.11+ |
| Web Framework | FastAPI + Uvicorn |
| Graph Store | Elasticsearch 8.x |
| LLM | Ollama (local, any GGUF model) |
| LLM Client | httpx (async) |
| Entity Extraction | Jinja2 prompts → JSON triples |
| Frontend | Vanilla JS + D3.js |
| Containerization | Docker + Docker Compose |
| IDE Integration | MCP (Model Context Protocol) via FastMCP |
| Data Exchange | STIX 2.1 (import/export) |
