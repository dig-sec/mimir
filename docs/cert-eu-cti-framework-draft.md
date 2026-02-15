# CERT-EU CTI Framework Integration Draft

Date: 2026-02-13
Source: https://www.cert.europa.eu/publications/threat-intelligence/cyber-threat-intelligence-framework/

## Goal

Integrate CERT-EU's CTI framework concepts into Mimir so the platform can:

1. Precompute daily CTI assessments (fast UI reads).
2. Track threat posture trends over time.
3. Represent uncertainty explicitly (confidence + attribution state).
4. Prioritize mitigations from observed activity.

## Current Baseline in Mimir

What already exists:

- Daily threat-actor rollup in metrics index.
- Daily PIR rollup in metrics index.
- Provenance-backed evidence counting.
- Trend UI with sparklines.

Main gaps vs framework:

- No explicit threat domain level model.
- No explicit threat actor level model (separate from raw evidence counts).
- No explicit composite threat level model.
- No Admiralty-style reliability/credibility fields.
- No formal attribution state model (known/suspected/unknown/UTA).
- No mitigation priority score exposed in API/UI.

## Proposed Data Model

Store CTI assessments in the existing metrics index (`<prefix>-metrics`) using a new metric type.

### Metric Type

- `metric_type = "daily_cti_assessment"`

### Document Shape

```json
{
  "metric_type": "daily_cti_assessment",
  "source_scope": "__all__",
  "bucket_start": "2026-02-13T00:00:00+00:00",

  "assessment_id": "mai:actor--123:uses_technique:T1059",
  "assessment_name": "Actor X uses T1059",
  "assessment_kind": "activity",

  "domain_key": "sector:energy",
  "domain_name": "Energy",
  "actor_id": "threat-actor--123",
  "actor_name": "Actor X",
  "entity_ids": ["threat-actor--123", "attack-pattern--T1059"],

  "threat_domain_score": 0.72,
  "threat_actor_score": 0.81,
  "threat_level_score": 0.78,

  "threat_domain_level": 4,
  "threat_actor_level": 4,
  "threat_level": 4,

  "confidence_score": 0.74,
  "source_reliability": "B",
  "information_credibility": "2",

  "attribution_state": "suspected",
  "attribution_target_id": "threat-actor--123",
  "attribution_text": "Likely linked to Actor X",

  "mitigation_priority_score": 0.69,
  "top_mitigations": [
    {"entity_id": "coa--1", "name": "Disable PowerShell", "score": 0.84}
  ],

  "evidence_count": 143,
  "relation_count": 27,
  "top_predicates": [
    {"predicate": "uses_technique", "count": 51},
    {"predicate": "targets_sector", "count": 32}
  ],

  "decay_half_life_days": 14,
  "lookback_days": 365,
  "min_confidence": 0.2,
  "rollup_generated_at": "2026-02-13T18:22:11.124Z"
}
```

### Index Mapping Additions

Add properties in `ElasticMetricsStore` mapping for:

- `assessment_id`, `assessment_name`, `assessment_kind`
- `domain_key`, `domain_name`
- `actor_id`, `actor_name`
- `entity_ids` (keyword array)
- `threat_domain_score`, `threat_actor_score`, `threat_level_score` (float)
- `threat_domain_level`, `threat_actor_level`, `threat_level` (integer)
- `confidence_score` (float)
- `source_reliability`, `information_credibility` (keyword)
- `attribution_state`, `attribution_target_id` (keyword), `attribution_text` (text/keyword)
- `mitigation_priority_score` (float)
- `top_mitigations` (nested/object with id/name/score)
- `decay_half_life_days` (integer)

## Assessment Logic (Daily Rollup)

Implement in `ElasticMetricsStore.rollup_daily_cti_assessments(...)`.

### Windows

- Current rolling evidence window: `lookback_days`.
- Daily output granularity: `bucket_start = 00:00:00Z` per day.
- Recency decay: exponential decay by event age.

### Scores

All scores normalized `0.0..1.0`.

- `domain_signal`: weighted evidence affecting a domain/sector.
- `actor_signal`: weighted evidence tied to actor activity and capability patterns.
- `activity_signal`: weighted MAI signal (actor + behavior/object tuple).
- `confidence_signal`: blend of reliability/credibility if present, fallback to relation confidence.

Proposed composite:

- `threat_domain_score = clamp(domain_signal)`
- `threat_actor_score = clamp(actor_signal)`
- `threat_level_score = clamp(0.40 * activity_signal + 0.35 * actor_signal + 0.25 * domain_signal)`

Discrete levels (`1..5`):

- `1`: `<0.20`
- `2`: `0.20..0.39`
- `3`: `0.40..0.59`
- `4`: `0.60..0.79`
- `5`: `>=0.80`

### Decay

For each evidence event:

- `weight = exp(-ln(2) * age_days / decay_half_life_days)`

Default:

- `decay_half_life_days = 14`

### Attribution State

Per assessment/day:

- `known`: clear actor/entity link with strong confidence.
- `suspected`: actor/entity link with medium confidence.
- `possible`: weak indicators.
- `unknown`: no credible attribution candidate.
- Optional placeholder entity: `UTA:<domain_or_activity_key>` for unknown threat actors.

### Confidence Fallback

If no explicit reliability/credibility fields exist in provenance:

- derive `confidence_score` from relation confidence + source consistency.
- map to default Admiralty buckets:
  - `>=0.85 -> B2`
  - `>=0.70 -> C3`
  - `>=0.50 -> D4`
  - otherwise `E5`

## API Draft

### 1) Trigger CTI Rollup

- `POST /api/metrics/rollup?include_cti=1`
- Keep current endpoint; extend task detail:

```json
{
  "threat_actor": {...},
  "pir": {...},
  "cti": {
    "metric_type": "daily_cti_assessment",
    "docs_written": 1234,
    "buckets_written": 432,
    "assessment_total": 311
  }
}
```

### 2) CTI Overview

- `GET /api/cti/overview?days=30&source_uri=...`
- Returns:
  - distribution by `threat_level` and `attribution_state`
  - top risky assessments
  - latest rollup timestamp

### 3) CTI Trends

- `GET /api/cti/trends?days=90&group_by=domain|actor|activity&top_n=10`
- Returns per item:
  - current vs previous windows
  - delta
  - daily `history[]` points

### 4) CTI Assessment Detail

- `GET /api/cti/assessment/{assessment_id}?days=30`
- Returns:
  - score/level history
  - top evidence predicates
  - attribution timeline
  - mitigation priority timeline

## UI Draft

Add a `CTI` page/tab with three sections:

1. `Threat Levels`:
   - distribution chart (levels 1..5)
   - top assessments by `threat_level_score`
2. `Attribution`:
   - counts by `known/suspected/possible/unknown`
   - list with confidence chips (`B2`, `C3`, etc.)
3. `Mitigation Priority`:
   - ranked mitigations from top active assessments
   - trend sparkline per mitigation candidate

Reuse existing PIR visual patterns:

- card layout, sparkline component style, range filters (`days/since/until`).

## Config Draft

Add in `config.py`:

- `CTI_ROLLUP_ENABLED` (default `1`)
- `CTI_ROLLUP_INTERVAL_SECONDS` (default aligns with metrics rollup interval)
- `CTI_ROLLUP_LOOKBACK_DAYS` (default `365`)
- `CTI_DECAY_HALF_LIFE_DAYS` (default `14`)
- `CTI_LEVEL_THRESHOLDS` (default `0.2,0.4,0.6,0.8`)

## Code Touchpoints

Backend:

- `src/mimir/storage/metrics_store.py`
- `src/mimir/storage/elastic_store.py`
- `src/mimir/api/routes/`
- `src/mimir/worker/llm_worker.py`

Frontend:

- `src/mimir/api/static/main.js`
- `src/mimir/api/static/style.css`
- `src/mimir/api/static/cti.js` (new)
- `src/mimir/api/ui.py`

## Phased Delivery

Phase 1 (MVP, low risk):

- Add metric schema + daily CTI rollup.
- Add `/api/cti/overview` and `/api/cti/trends`.
- Add CTI read-only page with trend cards and sparklines.

Phase 2:

- Add attribution timeline + UTA placeholder support.
- Add mitigation priority ranking endpoint.

Phase 3:

- Ingest explicit reliability/credibility fields from connectors/OpenCTI.
- Tune score weights from analyst feedback.

## Validation Plan

Automated tests:

- Score normalization and level-threshold unit tests.
- Decay function tests with fixed timestamps.
- Rollup integration test writes deterministic docs.
- API contract tests for `/api/cti/*`.

Operational checks:

- Rollup duration and doc counts in `/api/tasks/{id}`.
- Staleness indicator in `/api/stats` style status.
- Query latency p50/p95 for CTI endpoints.

## Open Decisions

1. Should MAI be first-class entities in graph (`type=malicious_activity`) or remain rollup-only keys?
2. Should `CTI` reuse `/api/metrics/rollup` only, or get a dedicated `/api/cti/rollup` endpoint?
3. Do we require explicit reliability/credibility at ingest time, or allow confidence-derived fallback indefinitely?
