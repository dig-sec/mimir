from __future__ import annotations

import math
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from elasticsearch.helpers import bulk as es_bulk

from ...lake import infer_source
from ..metrics_store import MetricsStore
from ._helpers import (
    _ElasticBase,
    _parse_datetime,
)


class ElasticMetricsStore(_ElasticBase, MetricsStore):
    METRIC_TYPE_DAILY_THREAT_ACTOR = "daily_threat_actor"
    METRIC_TYPE_DAILY_PIR_ENTITY = "daily_pir_entity"
    METRIC_TYPE_DAILY_CTI_ASSESSMENT = "daily_cti_assessment"
    GLOBAL_SCOPE = "__all__"
    PIR_ENTITY_TYPES = (
        "malware",
        "vulnerability",
        "threat_actor",
        "attack_pattern",
        "infrastructure",
        "campaign",
        "indicator",
        "malware_sample",
        "capa_rule",
        "yara_rule",
    )
    PIR_QUESTIONS = {
        "malware": "What malware families are trending?",
        "vulnerability": "Which CVEs / vulnerabilities are trending?",
        "threat_actor": "Which threat actors are trending?",
        "attack_pattern": "Which ATT&CK techniques are trending?",
        "infrastructure": "What infrastructure is being targeted?",
        "campaign": "Which campaigns are active?",
        "indicator": "What IOCs are trending?",
        "malware_sample": "What malware samples are appearing?",
        "capa_rule": "Which Capa capabilities are being detected?",
        "yara_rule": "Which Yara rules are matching?",
    }
    CTI_LEVEL_THRESHOLDS = (0.2, 0.4, 0.6, 0.8)
    CTI_ATTRIBUTION_STATES = ("known", "suspected", "possible", "unknown")
    CTI_SOURCE_CONFIDENCE_DEFAULTS = {
        "opencti": 0.90,
        "malware": 0.88,
        "feedly": 0.78,
        "elasticsearch": 0.72,
        "stix": 0.75,
        "upload": 0.55,
        "file": 0.50,
        "unknown": 0.45,
    }

    def __init__(
        self,
        hosts: List[str],
        username: Optional[str] = None,
        password: Optional[str] = None,
        index_prefix: str = "mimir",
        verify_certs: bool = True,
        cti_level_thresholds: Optional[List[float]] = None,
        cti_source_confidence_rules: Optional[Dict[str, float]] = None,
    ) -> None:
        super().__init__(hosts, username, password, index_prefix, verify_certs)
        self.cti_level_thresholds = self._normalize_level_thresholds(
            cti_level_thresholds
        )
        self.cti_source_confidence_rules = self._normalize_source_confidence_rules(
            cti_source_confidence_rules
        )
        self._ensure_indices()

    def _ensure_indices(self) -> None:
        self._ensure_index(
            self.indices.metrics,
            {
                "metric_type": {"type": "keyword"},
                "source_scope": {"type": "keyword"},
                "bucket_start": {"type": "date"},
                "entity_id": {"type": "keyword"},
                "entity_name": {"type": "keyword"},
                "entity_type": {"type": "keyword"},
                "assessment_id": {"type": "keyword"},
                "assessment_name": {"type": "keyword"},
                "assessment_kind": {"type": "keyword"},
                "domain_key": {"type": "keyword"},
                "domain_name": {"type": "keyword"},
                "actor_id": {"type": "keyword"},
                "actor_name": {"type": "keyword"},
                "entity_ids": {"type": "keyword"},
                "relation_count": {"type": "integer"},
                "incoming_relation_count": {"type": "integer"},
                "outgoing_relation_count": {"type": "integer"},
                "evidence_count": {"type": "integer"},
                "weighted_evidence_count": {"type": "float"},
                "source_confidence_score": {"type": "float"},
                "source_distribution": {"type": "object"},
                "threat_domain_score": {"type": "float"},
                "threat_actor_score": {"type": "float"},
                "threat_level_score": {"type": "float"},
                "threat_domain_level": {"type": "integer"},
                "threat_actor_level": {"type": "integer"},
                "threat_level": {"type": "integer"},
                "confidence_score": {"type": "float"},
                "source_reliability": {"type": "keyword"},
                "information_credibility": {"type": "keyword"},
                "attribution_state": {"type": "keyword"},
                "attribution_target_id": {"type": "keyword"},
                "attribution_text": {"type": "text"},
                "mitigation_priority_score": {"type": "float"},
                "top_mitigations": {"type": "object"},
                "decay_half_life_days": {"type": "integer"},
                "top_predicates": {"type": "object"},
                "lookback_days": {"type": "integer"},
                "min_confidence": {"type": "float"},
                "rollup_generated_at": {"type": "date"},
            },
        )

    @staticmethod
    def _bucket_day(ts: datetime) -> datetime:
        if ts.tzinfo is not None:
            ts = ts.astimezone(timezone.utc).replace(tzinfo=None)
        return ts.replace(hour=0, minute=0, second=0, microsecond=0)

    def _source_scope(self, source_uri: Optional[str]) -> str:
        return source_uri or self.GLOBAL_SCOPE

    @staticmethod
    def _daily_window_bounds(
        *,
        days: int,
        since: Optional[datetime],
        until: Optional[datetime],
    ) -> Tuple[int, datetime, datetime]:
        now = datetime.now(timezone.utc)
        if since and until:
            current_since = (
                since
                if since.tzinfo is not None
                else since.replace(tzinfo=timezone.utc)
            ).astimezone(timezone.utc)
            current_until = (
                until
                if until.tzinfo is not None
                else until.replace(tzinfo=timezone.utc)
            ).astimezone(timezone.utc)
            if current_since >= current_until:
                current_since = current_until - timedelta(days=1)
            duration_seconds = max(
                int((current_until - current_since).total_seconds()),
                1,
            )
            window_days = max(1, (duration_seconds + 86399) // 86400)
            return window_days, current_since, current_until

        window_days = max(1, int(days))
        current_until = now
        current_since = now - timedelta(days=window_days)
        return window_days, current_since, current_until

    @staticmethod
    def _iter_day_starts(start: datetime, end: datetime) -> List[datetime]:
        cursor = start.replace(hour=0, minute=0, second=0, microsecond=0)
        out: List[datetime] = []
        while cursor < end:
            out.append(cursor)
            cursor += timedelta(days=1)
        return out

    @staticmethod
    def _clamp_score(value: float) -> float:
        return max(0.0, min(float(value), 1.0))

    @classmethod
    def _normalize_level_thresholds(
        cls,
        values: Optional[List[float]],
    ) -> Tuple[float, float, float, float]:
        if not values:
            return cls.CTI_LEVEL_THRESHOLDS
        parsed = sorted(
            {
                float(value)
                for value in values
                if isinstance(value, (int, float)) and 0.0 <= float(value) <= 1.0
            }
        )
        if len(parsed) < 4:
            return cls.CTI_LEVEL_THRESHOLDS
        return (parsed[0], parsed[1], parsed[2], parsed[3])

    @classmethod
    def _normalize_source_confidence_rules(
        cls,
        values: Optional[Dict[str, float]],
    ) -> Dict[str, float]:
        normalized = dict(cls.CTI_SOURCE_CONFIDENCE_DEFAULTS)
        if not values:
            return normalized
        for key, value in values.items():
            normalized_key = str(key or "").strip().lower()
            if not normalized_key:
                continue
            try:
                score = float(value)
            except (TypeError, ValueError):
                continue
            normalized[normalized_key] = max(0.0, min(score, 1.0))
        if "unknown" not in normalized:
            normalized["unknown"] = cls.CTI_SOURCE_CONFIDENCE_DEFAULTS["unknown"]
        return normalized

    def _source_confidence_for_uri(self, source_uri: Any) -> Tuple[str, float]:
        source_key = infer_source(str(source_uri or "")).strip().lower() or "unknown"
        score = self.cti_source_confidence_rules.get(source_key)
        if score is None:
            score = self.cti_source_confidence_rules.get("unknown", 0.45)
        return source_key, self._clamp_score(score)

    def _score_to_level(self, score: float) -> int:
        score = self._clamp_score(score)
        thresholds = self.cti_level_thresholds
        if score < thresholds[0]:
            return 1
        if score < thresholds[1]:
            return 2
        if score < thresholds[2]:
            return 3
        if score < thresholds[3]:
            return 4
        return 5

    @staticmethod
    def _infer_domain(
        entity_type: str,
        entity_attrs: Dict[str, Any],
    ) -> Tuple[str, str]:
        for key in ("sector", "industry", "target_sector", "target_industry"):
            value = entity_attrs.get(key)
            if isinstance(value, list):
                value = next(
                    (str(item).strip() for item in value if str(item).strip()),
                    "",
                )
            elif value is None:
                value = ""
            else:
                value = str(value).strip()
            if value:
                normalized = value.lower().replace(" ", "_")
                return f"sector:{normalized}", value
        fallback = entity_type or "unknown"
        return f"type:{fallback}", fallback.replace("_", " ").title()

    @staticmethod
    def _confidence_to_admiralty(confidence_score: float) -> Tuple[str, str]:
        confidence_score = max(0.0, min(float(confidence_score), 1.0))
        if confidence_score >= 0.85:
            return "B", "2"
        if confidence_score >= 0.70:
            return "C", "3"
        if confidence_score >= 0.50:
            return "D", "4"
        return "E", "5"

    @staticmethod
    def _heuristic_mitigations(
        entity_type: str,
        top_predicates: List[Dict[str, Any]],
        base_score: float,
    ) -> List[Dict[str, Any]]:
        names: List[str] = []
        predicates = {str(item.get("predicate") or "") for item in top_predicates}
        if "exploits_vulnerability" in predicates or entity_type == "vulnerability":
            names.extend(
                [
                    "Prioritize patching of exposed systems",
                    "Deploy compensating controls for unpatched assets",
                ]
            )
        if "uses_technique" in predicates or entity_type == "attack_pattern":
            names.extend(
                [
                    "Strengthen detection rules for observed techniques",
                    "Harden endpoint controls and execution policies",
                ]
            )
        if entity_type == "malware":
            names.extend(
                [
                    "Update malware signatures and EDR policies",
                    "Isolate infected hosts and rotate credentials",
                ]
            )
        if entity_type == "infrastructure":
            names.extend(
                [
                    "Block malicious infrastructure indicators",
                    "Enforce egress filtering and DNS monitoring",
                ]
            )
        if entity_type == "threat_actor":
            names.extend(
                [
                    "Increase monitoring on likely actor TTPs",
                    "Review exposed perimeter services",
                ]
            )
        if not names:
            names = [
                "Increase monitoring and triage related activity",
                "Apply preventive controls to exposed attack paths",
            ]
        unique_names: List[str] = []
        for name in names:
            if name not in unique_names:
                unique_names.append(name)
        out: List[Dict[str, Any]] = []
        for idx, name in enumerate(unique_names[:3]):
            score = max(0.0, min(base_score - (idx * 0.08), 1.0))
            out.append(
                {
                    "entity_id": f"heuristic:{entity_type}:{idx + 1}",
                    "name": name,
                    "score": round(score, 4),
                }
            )
        return out

    def rollup_daily_threat_actor_stats(
        self,
        lookback_days: int = 365,
        min_confidence: float = 0.0,
        source_uri: Optional[str] = None,
    ) -> Dict[str, Any]:
        lookback_days = max(int(lookback_days), 1)
        min_confidence = max(0.0, min(1.0, float(min_confidence)))

        now = datetime.utcnow()
        since = now - timedelta(days=lookback_days)
        scope = self._source_scope(source_uri)

        actor_hits = list(
            self._iter_search_hits(
                self.indices.entities,
                query={"term": {"type": "threat_actor"}},
                sort=[{"_id": "asc"}],
            )
        )
        actor_names = {
            hit["_id"]: str(hit["_source"].get("name") or hit["_id"])
            for hit in actor_hits
        }
        actor_ids = set(actor_names.keys())
        if not actor_ids:
            return {
                "metric_type": self.METRIC_TYPE_DAILY_THREAT_ACTOR,
                "source_scope": scope,
                "lookback_days": lookback_days,
                "min_confidence": min_confidence,
                "actors_total": 0,
                "relations_considered": 0,
                "buckets_written": 0,
                "docs_written": 0,
                "first_bucket": None,
                "last_bucket": None,
                "generated_at": now.isoformat(),
            }

        relation_meta: Dict[str, Dict[str, Any]] = {}
        actor_id_list = sorted(actor_ids)
        chunk_size = 500
        for i in range(0, len(actor_id_list), chunk_size):
            actor_chunk = actor_id_list[i : i + chunk_size]
            relation_query: Dict[str, Any] = {
                "bool": {
                    "should": [
                        {"terms": {"subject_id": actor_chunk}},
                        {"terms": {"object_id": actor_chunk}},
                    ],
                    "minimum_should_match": 1,
                    "filter": [{"range": {"confidence": {"gte": min_confidence}}}],
                }
            }
            for hit in self._iter_search_hits(
                self.indices.relations,
                query=relation_query,
                sort=[{"_id": "asc"}],
            ):
                relation_id = hit["_id"]
                source = hit["_source"]
                subject_id = source.get("subject_id")
                object_id = source.get("object_id")
                predicate = source.get("predicate", "related_to")
                roles: List[Tuple[str, str]] = []
                if subject_id in actor_ids:
                    roles.append((subject_id, "outgoing"))
                if object_id in actor_ids:
                    roles.append((object_id, "incoming"))
                if not roles:
                    continue
                relation_meta[relation_id] = {
                    "predicate": predicate,
                    "roles": roles,
                }

        if not relation_meta:
            return {
                "metric_type": self.METRIC_TYPE_DAILY_THREAT_ACTOR,
                "source_scope": scope,
                "lookback_days": lookback_days,
                "min_confidence": min_confidence,
                "actors_total": len(actor_ids),
                "relations_considered": 0,
                "buckets_written": 0,
                "docs_written": 0,
                "first_bucket": None,
                "last_bucket": None,
                "generated_at": now.isoformat(),
            }

        self.client.delete_by_query(
            index=self.indices.metrics,
            query={
                "bool": {
                    "filter": [
                        {"term": {"metric_type": self.METRIC_TYPE_DAILY_THREAT_ACTOR}},
                        {"term": {"source_scope": scope}},
                        {"range": {"bucket_start": {"gte": since.isoformat()}}},
                    ]
                }
            },
            refresh=False,
            conflicts="proceed",
        )

        buckets: Dict[Tuple[str, datetime], Dict[str, Any]] = {}
        relation_ids = sorted(relation_meta.keys())
        relation_chunk_size = 500

        for i in range(0, len(relation_ids), relation_chunk_size):
            relation_chunk = relation_ids[i : i + relation_chunk_size]
            filters: List[Dict[str, Any]] = [
                {"terms": {"relation_id": relation_chunk}},
                {"range": {"timestamp": {"gte": since.isoformat()}}},
            ]
            if source_uri:
                filters.append({"term": {"source_uri": source_uri}})
            query = {"bool": {"filter": filters}}
            for hit in self._iter_search_hits(
                self.indices.relation_provenance,
                query=query,
                sort=[{"timestamp": "asc"}, {"_id": "asc"}],
                size=1000,
            ):
                source = hit["_source"]
                relation_id = str(source.get("relation_id"))
                if relation_id not in relation_meta:
                    continue
                relation = relation_meta[relation_id]
                ts = _parse_datetime(source.get("timestamp"))
                bucket_day = self._bucket_day(ts)
                for actor_id, direction in relation["roles"]:
                    key = (actor_id, bucket_day)
                    if key not in buckets:
                        buckets[key] = {
                            "relation_ids": set(),
                            "incoming_ids": set(),
                            "outgoing_ids": set(),
                            "evidence_count": 0,
                            "predicates": Counter(),
                        }
                    data = buckets[key]
                    data["relation_ids"].add(relation_id)
                    if direction == "incoming":
                        data["incoming_ids"].add(relation_id)
                    if direction == "outgoing":
                        data["outgoing_ids"].add(relation_id)
                    data["evidence_count"] += 1
                    data["predicates"][relation["predicate"]] += 1

        docs_written = 0
        generated_at = now.isoformat()
        first_bucket: Optional[datetime] = None
        last_bucket: Optional[datetime] = None

        bulk_actions: List[Dict[str, Any]] = []
        for (actor_id, bucket_day), data in buckets.items():
            if first_bucket is None or bucket_day < first_bucket:
                first_bucket = bucket_day
            if last_bucket is None or bucket_day > last_bucket:
                last_bucket = bucket_day

            top_predicates = [
                {"predicate": pred, "count": count}
                for pred, count in data["predicates"].most_common(10)
            ]
            doc_id = (
                f"{self.METRIC_TYPE_DAILY_THREAT_ACTOR}:"
                f"{scope}:{bucket_day.date().isoformat()}:{actor_id}"
            )
            bulk_actions.append(
                {
                    "_op_type": "index",
                    "_index": self.indices.metrics,
                    "_id": doc_id,
                    "_source": {
                        "metric_type": self.METRIC_TYPE_DAILY_THREAT_ACTOR,
                        "source_scope": scope,
                        "bucket_start": bucket_day.isoformat(),
                        "entity_id": actor_id,
                        "entity_name": actor_names.get(actor_id, actor_id),
                        "relation_count": len(data["relation_ids"]),
                        "incoming_relation_count": len(data["incoming_ids"]),
                        "outgoing_relation_count": len(data["outgoing_ids"]),
                        "evidence_count": int(data["evidence_count"]),
                        "top_predicates": top_predicates,
                        "lookback_days": lookback_days,
                        "min_confidence": min_confidence,
                        "rollup_generated_at": generated_at,
                    },
                }
            )

        if bulk_actions:
            success, _ = es_bulk(self.client, bulk_actions, raise_on_error=False)
            docs_written = success

        self.client.indices.refresh(index=self.indices.metrics)

        return {
            "metric_type": self.METRIC_TYPE_DAILY_THREAT_ACTOR,
            "source_scope": scope,
            "lookback_days": lookback_days,
            "min_confidence": min_confidence,
            "actors_total": len(actor_ids),
            "relations_considered": len(relation_meta),
            "buckets_written": len(buckets),
            "docs_written": docs_written,
            "first_bucket": first_bucket.isoformat() if first_bucket else None,
            "last_bucket": last_bucket.isoformat() if last_bucket else None,
            "generated_at": generated_at,
        }

    def rollup_daily_pir_stats(
        self,
        lookback_days: int = 365,
        min_confidence: float = 0.0,
        source_uri: Optional[str] = None,
    ) -> Dict[str, Any]:
        lookback_days = max(int(lookback_days), 1)
        min_confidence = max(0.0, min(1.0, float(min_confidence)))

        now = datetime.utcnow()
        since = now - timedelta(days=lookback_days)
        scope = self._source_scope(source_uri)

        entity_hits = list(
            self._iter_search_hits(
                self.indices.entities,
                query={"terms": {"type": list(self.PIR_ENTITY_TYPES)}},
                sort=[{"_id": "asc"}],
            )
        )
        entity_meta = {
            hit["_id"]: {
                "name": str(hit["_source"].get("name") or hit["_id"]),
                "type": str(hit["_source"].get("type") or "unknown"),
            }
            for hit in entity_hits
        }
        entity_ids = set(entity_meta.keys())
        if not entity_ids:
            return {
                "metric_type": self.METRIC_TYPE_DAILY_PIR_ENTITY,
                "source_scope": scope,
                "lookback_days": lookback_days,
                "min_confidence": min_confidence,
                "entities_total": 0,
                "relations_considered": 0,
                "buckets_written": 0,
                "docs_written": 0,
                "first_bucket": None,
                "last_bucket": None,
                "generated_at": now.isoformat(),
            }

        relation_meta: Dict[str, Dict[str, Any]] = {}
        entity_id_list = sorted(entity_ids)
        chunk_size = 500
        for i in range(0, len(entity_id_list), chunk_size):
            entity_chunk = entity_id_list[i : i + chunk_size]
            relation_query: Dict[str, Any] = {
                "bool": {
                    "should": [
                        {"terms": {"subject_id": entity_chunk}},
                        {"terms": {"object_id": entity_chunk}},
                    ],
                    "minimum_should_match": 1,
                    "filter": [{"range": {"confidence": {"gte": min_confidence}}}],
                }
            }
            for hit in self._iter_search_hits(
                self.indices.relations,
                query=relation_query,
                sort=[{"_id": "asc"}],
            ):
                relation_id = hit["_id"]
                source = hit["_source"]
                subject_id = source.get("subject_id")
                object_id = source.get("object_id")
                predicate = source.get("predicate", "related_to")
                candidate_entity_ids: List[str] = []
                subject_meta = entity_meta.get(str(subject_id))
                object_meta = entity_meta.get(str(object_id))
                if subject_meta:
                    candidate_entity_ids.append(str(subject_id))
                if object_meta and str(object_id) != str(subject_id):
                    candidate_entity_ids.append(str(object_id))
                if not candidate_entity_ids:
                    continue
                relation_meta[relation_id] = {
                    "predicate": predicate,
                    "entity_ids": candidate_entity_ids,
                }

        if not relation_meta:
            return {
                "metric_type": self.METRIC_TYPE_DAILY_PIR_ENTITY,
                "source_scope": scope,
                "lookback_days": lookback_days,
                "min_confidence": min_confidence,
                "entities_total": len(entity_ids),
                "relations_considered": 0,
                "buckets_written": 0,
                "docs_written": 0,
                "first_bucket": None,
                "last_bucket": None,
                "generated_at": now.isoformat(),
            }

        self.client.delete_by_query(
            index=self.indices.metrics,
            query={
                "bool": {
                    "filter": [
                        {"term": {"metric_type": self.METRIC_TYPE_DAILY_PIR_ENTITY}},
                        {"term": {"source_scope": scope}},
                        {"range": {"bucket_start": {"gte": since.isoformat()}}},
                    ]
                }
            },
            refresh=False,
            conflicts="proceed",
        )

        buckets: Dict[Tuple[str, datetime], Dict[str, Any]] = {}
        relation_ids = sorted(relation_meta.keys())
        relation_chunk_size = 500

        for i in range(0, len(relation_ids), relation_chunk_size):
            relation_chunk = relation_ids[i : i + relation_chunk_size]
            filters: List[Dict[str, Any]] = [
                {"terms": {"relation_id": relation_chunk}},
                {"range": {"timestamp": {"gte": since.isoformat()}}},
            ]
            if source_uri:
                filters.append({"term": {"source_uri": source_uri}})
            query = {"bool": {"filter": filters}}
            for hit in self._iter_search_hits(
                self.indices.relation_provenance,
                query=query,
                sort=[{"timestamp": "asc"}, {"_id": "asc"}],
                size=1000,
            ):
                source = hit["_source"]
                relation_id = str(source.get("relation_id"))
                relation = relation_meta.get(relation_id)
                if not relation:
                    continue
                ts = _parse_datetime(source.get("timestamp"))
                bucket_day = self._bucket_day(ts)
                for entity_id in relation["entity_ids"]:
                    key = (entity_id, bucket_day)
                    if key not in buckets:
                        buckets[key] = {
                            "relation_ids": set(),
                            "evidence_count": 0,
                            "predicates": Counter(),
                            "source_counts": Counter(),
                            "source_weight_sum": 0.0,
                            "source_samples": 0,
                        }
                    data = buckets[key]
                    data["relation_ids"].add(relation_id)
                    data["evidence_count"] += 1
                    data["predicates"][relation["predicate"]] += 1
                    source_key, source_score = self._source_confidence_for_uri(
                        source.get("source_uri")
                    )
                    data["source_counts"][source_key] += 1
                    data["source_weight_sum"] += source_score
                    data["source_samples"] += 1

        docs_written = 0
        generated_at = now.isoformat()
        first_bucket: Optional[datetime] = None
        last_bucket: Optional[datetime] = None

        bulk_actions: List[Dict[str, Any]] = []
        for (entity_id, bucket_day), data in buckets.items():
            if first_bucket is None or bucket_day < first_bucket:
                first_bucket = bucket_day
            if last_bucket is None or bucket_day > last_bucket:
                last_bucket = bucket_day

            meta = entity_meta.get(entity_id, {"name": entity_id, "type": "unknown"})
            top_predicates = [
                {"predicate": pred, "count": count}
                for pred, count in data["predicates"].most_common(10)
            ]
            source_samples = int(data.get("source_samples", 0))
            source_confidence_score = self._clamp_score(
                float(data.get("source_weight_sum", 0.0))
                / float(max(source_samples, 1))
            )
            weighted_evidence_count = (
                float(data.get("source_weight_sum", 0.0))
                if source_samples > 0
                else float(data.get("evidence_count", 0))
            )
            source_distribution = [
                {"source": str(source_name), "count": int(count)}
                for source_name, count in data.get(
                    "source_counts", Counter()
                ).most_common(10)
            ]
            doc_id = (
                f"{self.METRIC_TYPE_DAILY_PIR_ENTITY}:"
                f"{scope}:{bucket_day.date().isoformat()}:{entity_id}"
            )
            bulk_actions.append(
                {
                    "_op_type": "index",
                    "_index": self.indices.metrics,
                    "_id": doc_id,
                    "_source": {
                        "metric_type": self.METRIC_TYPE_DAILY_PIR_ENTITY,
                        "source_scope": scope,
                        "bucket_start": bucket_day.isoformat(),
                        "entity_id": entity_id,
                        "entity_name": meta["name"],
                        "entity_type": meta["type"],
                        "relation_count": len(data["relation_ids"]),
                        "evidence_count": int(data["evidence_count"]),
                        "weighted_evidence_count": round(weighted_evidence_count, 4),
                        "source_confidence_score": round(source_confidence_score, 4),
                        "source_distribution": source_distribution,
                        "top_predicates": top_predicates,
                        "lookback_days": lookback_days,
                        "min_confidence": min_confidence,
                        "rollup_generated_at": generated_at,
                    },
                }
            )

        if bulk_actions:
            success, _ = es_bulk(self.client, bulk_actions, raise_on_error=False)
            docs_written = success

        self.client.indices.refresh(index=self.indices.metrics)

        return {
            "metric_type": self.METRIC_TYPE_DAILY_PIR_ENTITY,
            "source_scope": scope,
            "lookback_days": lookback_days,
            "min_confidence": min_confidence,
            "entities_total": len(entity_ids),
            "relations_considered": len(relation_meta),
            "buckets_written": len(buckets),
            "docs_written": docs_written,
            "first_bucket": first_bucket.isoformat() if first_bucket else None,
            "last_bucket": last_bucket.isoformat() if last_bucket else None,
            "generated_at": generated_at,
        }

    def rollup_daily_cti_assessments(
        self,
        lookback_days: int = 365,
        min_confidence: float = 0.0,
        source_uri: Optional[str] = None,
        decay_half_life_days: int = 14,
    ) -> Dict[str, Any]:
        lookback_days = max(int(lookback_days), 1)
        min_confidence = max(0.0, min(1.0, float(min_confidence)))
        decay_half_life_days = max(int(decay_half_life_days), 1)

        now = datetime.now(timezone.utc)
        since = now - timedelta(days=lookback_days)
        scope = self._source_scope(source_uri)

        self.client.delete_by_query(
            index=self.indices.metrics,
            query={
                "bool": {
                    "filter": [
                        {
                            "term": {
                                "metric_type": self.METRIC_TYPE_DAILY_CTI_ASSESSMENT
                            }
                        },
                        {"term": {"source_scope": scope}},
                        {"range": {"bucket_start": {"gte": since.isoformat()}}},
                    ]
                }
            },
            refresh=False,
            conflicts="proceed",
        )

        filters: List[Dict[str, Any]] = [
            {"term": {"metric_type": self.METRIC_TYPE_DAILY_PIR_ENTITY}},
            {"term": {"source_scope": scope}},
            {"range": {"bucket_start": {"gte": since.isoformat()}}},
            {"range": {"bucket_start": {"lt": now.isoformat()}}},
        ]
        pir_docs = self._iter_search_hits(
            self.indices.metrics,
            query={"bool": {"filter": filters}},
            sort=[{"bucket_start": "asc"}, {"_id": "asc"}],
            size=1000,
        )

        high_risk_predicates = {
            "exploits_vulnerability",
            "uses_technique",
            "delivers_malware",
            "targets_sector",
            "compromises",
        }
        docs_written = 0
        buckets_written = 0
        first_bucket: Optional[datetime] = None
        last_bucket: Optional[datetime] = None
        assessment_ids: set[str] = set()
        latest_pir_rollup_at: Optional[str] = None
        generated_at = now.isoformat()
        bulk_actions: List[Dict[str, Any]] = []

        for hit in pir_docs:
            source = hit.get("_source") or {}
            entity_id = str(source.get("entity_id") or "")
            if not entity_id:
                continue

            entity_type = str(source.get("entity_type") or "unknown")
            entity_name = str(source.get("entity_name") or entity_id)
            bucket_start_raw = source.get("bucket_start")
            if not bucket_start_raw:
                continue
            bucket_ts = _parse_datetime(bucket_start_raw)
            if bucket_ts.tzinfo is None:
                bucket_ts = bucket_ts.replace(tzinfo=timezone.utc)
            else:
                bucket_ts = bucket_ts.astimezone(timezone.utc)
            bucket_day = self._bucket_day(bucket_ts)
            if first_bucket is None or bucket_day < first_bucket:
                first_bucket = bucket_day
            if last_bucket is None or bucket_day > last_bucket:
                last_bucket = bucket_day
            buckets_written += 1

            relation_count = max(int(source.get("relation_count", 0)), 0)
            evidence_count = max(int(source.get("evidence_count", 0)), 0)
            weighted_evidence_count = max(
                float(source.get("weighted_evidence_count", evidence_count)),
                0.0,
            )
            source_confidence_score = self._clamp_score(
                source.get(
                    "source_confidence_score",
                    self.cti_source_confidence_rules.get("unknown", 0.45),
                )
            )
            source_distribution_raw = source.get("source_distribution") or []
            source_distribution = (
                source_distribution_raw
                if isinstance(source_distribution_raw, list)
                else []
            )
            top_predicates_raw = source.get("top_predicates") or []
            top_predicates = (
                top_predicates_raw if isinstance(top_predicates_raw, list) else []
            )
            age_days = max((now - bucket_ts).total_seconds() / 86400.0, 0.0)
            decay_weight = math.exp(
                (-math.log(2.0) * age_days) / float(decay_half_life_days)
            )

            raw_activity_signal = min(
                1.0, math.log1p(float(evidence_count)) / math.log1p(200.0)
            )
            weighted_activity_signal = min(
                1.0, math.log1p(float(weighted_evidence_count)) / math.log1p(200.0)
            )
            activity_signal_raw = self._clamp_score(
                (0.65 * weighted_activity_signal) + (0.35 * raw_activity_signal)
            )
            domain_signal_raw = min(
                1.0, math.log1p(float(relation_count)) / math.log1p(80.0)
            )
            actor_signal_raw = (
                activity_signal_raw
                if entity_type == "threat_actor"
                else activity_signal_raw * 0.60
            )
            activity_signal = self._clamp_score(activity_signal_raw * decay_weight)
            threat_domain_score = self._clamp_score(domain_signal_raw * decay_weight)
            threat_actor_score = self._clamp_score(actor_signal_raw * decay_weight)
            threat_level_score = self._clamp_score(
                0.40 * activity_signal
                + 0.35 * threat_actor_score
                + 0.25 * threat_domain_score
            )
            confidence_score = self._clamp_score(
                max(min_confidence, 0.20)
                + (0.35 * activity_signal)
                + (0.20 * threat_domain_score)
                + (0.25 * source_confidence_score)
            )
            source_reliability, information_credibility = self._confidence_to_admiralty(
                confidence_score
            )

            if entity_type == "threat_actor":
                if threat_level_score >= 0.65 and confidence_score >= 0.70:
                    attribution_state = "known"
                elif confidence_score >= 0.55:
                    attribution_state = "suspected"
                elif confidence_score >= 0.35:
                    attribution_state = "possible"
                else:
                    attribution_state = "unknown"
            else:
                if confidence_score >= 0.65:
                    attribution_state = "suspected"
                elif confidence_score >= 0.35:
                    attribution_state = "possible"
                else:
                    attribution_state = "unknown"
            attribution_target_id = (
                entity_id
                if entity_type == "threat_actor"
                and attribution_state in {"known", "suspected"}
                else None
            )
            attribution_text = {
                "known": "Observed activity confidently linked to actor",
                "suspected": "Likely linked to actor or campaign",
                "possible": "Weak or partial attribution indicators",
                "unknown": "Attribution not established (UTA)",
            }.get(attribution_state, "Attribution unknown")

            risk_modifier = 1.0
            if top_predicates:
                total_predicate_hits = sum(
                    max(int(item.get("count", 0)), 0) for item in top_predicates
                )
                risky_hits = sum(
                    max(int(item.get("count", 0)), 0)
                    for item in top_predicates
                    if str(item.get("predicate") or "") in high_risk_predicates
                )
                if total_predicate_hits > 0:
                    risk_modifier += (
                        min(risky_hits / float(total_predicate_hits), 1.0) * 0.25
                    )
            mitigation_priority_score = self._clamp_score(
                threat_level_score * risk_modifier
            )
            top_mitigations = self._heuristic_mitigations(
                entity_type=entity_type,
                top_predicates=top_predicates,
                base_score=mitigation_priority_score,
            )

            domain_key, domain_name = self._infer_domain(entity_type, {})
            assessment_id = f"activity:{entity_type}:{entity_id}"
            assessment_name = f"{entity_name} ({entity_type.replace('_', ' ')})"
            threat_domain_level = self._score_to_level(threat_domain_score)
            threat_actor_level = self._score_to_level(threat_actor_score)
            threat_level = self._score_to_level(threat_level_score)
            doc_id = (
                f"{self.METRIC_TYPE_DAILY_CTI_ASSESSMENT}:"
                f"{scope}:{bucket_day.date().isoformat()}:{assessment_id}"
            )
            bulk_actions.append(
                {
                    "_op_type": "index",
                    "_index": self.indices.metrics,
                    "_id": doc_id,
                    "_source": {
                        "metric_type": self.METRIC_TYPE_DAILY_CTI_ASSESSMENT,
                        "source_scope": scope,
                        "bucket_start": bucket_day.isoformat(),
                        "assessment_id": assessment_id,
                        "assessment_name": assessment_name,
                        "assessment_kind": "activity",
                        "domain_key": domain_key,
                        "domain_name": domain_name,
                        "actor_id": (
                            entity_id if entity_type == "threat_actor" else None
                        ),
                        "actor_name": (
                            entity_name if entity_type == "threat_actor" else None
                        ),
                        "entity_id": entity_id,
                        "entity_name": entity_name,
                        "entity_type": entity_type,
                        "entity_ids": [entity_id],
                        "relation_count": relation_count,
                        "evidence_count": evidence_count,
                        "weighted_evidence_count": round(weighted_evidence_count, 4),
                        "source_confidence_score": round(source_confidence_score, 4),
                        "source_distribution": source_distribution,
                        "threat_domain_score": threat_domain_score,
                        "threat_actor_score": threat_actor_score,
                        "threat_level_score": threat_level_score,
                        "threat_domain_level": threat_domain_level,
                        "threat_actor_level": threat_actor_level,
                        "threat_level": threat_level,
                        "confidence_score": confidence_score,
                        "source_reliability": source_reliability,
                        "information_credibility": information_credibility,
                        "attribution_state": attribution_state,
                        "attribution_target_id": attribution_target_id,
                        "attribution_text": attribution_text,
                        "mitigation_priority_score": mitigation_priority_score,
                        "top_mitigations": top_mitigations,
                        "top_predicates": top_predicates,
                        "lookback_days": lookback_days,
                        "min_confidence": min_confidence,
                        "decay_half_life_days": decay_half_life_days,
                        "rollup_generated_at": generated_at,
                    },
                }
            )
            assessment_ids.add(assessment_id)

            pir_rollup_at = source.get("rollup_generated_at")
            if pir_rollup_at and (
                not latest_pir_rollup_at
                or str(pir_rollup_at) > str(latest_pir_rollup_at)
            ):
                latest_pir_rollup_at = str(pir_rollup_at)

        if bulk_actions:
            success, _ = es_bulk(self.client, bulk_actions, raise_on_error=False)
            docs_written = success

        self.client.indices.refresh(index=self.indices.metrics)
        return {
            "metric_type": self.METRIC_TYPE_DAILY_CTI_ASSESSMENT,
            "source_scope": scope,
            "lookback_days": lookback_days,
            "min_confidence": min_confidence,
            "decay_half_life_days": decay_half_life_days,
            "assessments_total": len(assessment_ids),
            "buckets_written": buckets_written,
            "docs_written": docs_written,
            "first_bucket": first_bucket.isoformat() if first_bucket else None,
            "last_bucket": last_bucket.isoformat() if last_bucket else None,
            "pir_rollup_last_generated_at": latest_pir_rollup_at,
            "generated_at": generated_at,
        }

    def get_cti_overview(
        self,
        *,
        days: int = 30,
        source_uri: Optional[str] = None,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        window_days, current_since, current_until = self._daily_window_bounds(
            days=days,
            since=since,
            until=until,
        )
        scope = self._source_scope(source_uri)

        filters: List[Dict[str, Any]] = [
            {"term": {"metric_type": self.METRIC_TYPE_DAILY_CTI_ASSESSMENT}},
            {"term": {"source_scope": scope}},
            {"range": {"bucket_start": {"gte": current_since.isoformat()}}},
            {"range": {"bucket_start": {"lt": current_until.isoformat()}}},
        ]
        hits = self._iter_search_hits(
            self.indices.metrics,
            query={"bool": {"filter": filters}},
            sort=[{"bucket_start": "asc"}, {"_id": "asc"}],
            size=1000,
        )

        level_distribution: Counter[int] = Counter()
        attribution_distribution: Counter[str] = Counter()
        by_assessment: Dict[str, Dict[str, Any]] = {}
        rollup_generated_at: Optional[str] = None
        docs_total = 0

        for hit in hits:
            source = hit.get("_source") or {}
            docs_total += 1
            level = int(source.get("threat_level") or 1)
            level = max(1, min(level, 5))
            level_distribution[level] += 1

            state = str(source.get("attribution_state") or "unknown")
            if state not in self.CTI_ATTRIBUTION_STATES:
                state = "unknown"
            attribution_distribution[state] += 1

            assessment_id = str(source.get("assessment_id") or "")
            if not assessment_id:
                continue
            score = float(source.get("threat_level_score") or 0.0)
            evidence_count = int(source.get("evidence_count") or 0)
            relation_count = int(source.get("relation_count") or 0)
            item = by_assessment.setdefault(
                assessment_id,
                {
                    "assessment_id": assessment_id,
                    "assessment_name": str(
                        source.get("assessment_name") or assessment_id
                    ),
                    "assessment_kind": str(source.get("assessment_kind") or "activity"),
                    "entity_type": str(source.get("entity_type") or "unknown"),
                    "domain_name": str(source.get("domain_name") or "Unknown"),
                    "max_score": 0.0,
                    "score_sum": 0.0,
                    "evidence_total": 0,
                    "relation_total": 0,
                    "days": 0,
                },
            )
            item["max_score"] = max(float(item["max_score"]), score)
            item["score_sum"] = float(item["score_sum"]) + score
            item["evidence_total"] = int(item["evidence_total"]) + evidence_count
            item["relation_total"] = int(item["relation_total"]) + relation_count
            item["days"] = int(item["days"]) + 1

            latest_rollup = source.get("rollup_generated_at")
            if latest_rollup and (
                not rollup_generated_at or str(latest_rollup) > str(rollup_generated_at)
            ):
                rollup_generated_at = str(latest_rollup)

        top_assessments = []
        for item in by_assessment.values():
            days_with_data = max(int(item["days"]), 1)
            avg_score = self._clamp_score(
                float(item["score_sum"]) / float(days_with_data)
            )
            top_assessments.append(
                {
                    "assessment_id": item["assessment_id"],
                    "assessment_name": item["assessment_name"],
                    "assessment_kind": item["assessment_kind"],
                    "entity_type": item["entity_type"],
                    "domain_name": item["domain_name"],
                    "max_threat_level_score": round(float(item["max_score"]), 4),
                    "avg_threat_level_score": round(avg_score, 4),
                    "threat_level": self._score_to_level(avg_score),
                    "evidence_total": int(item["evidence_total"]),
                    "relation_total": int(item["relation_total"]),
                }
            )
        top_assessments.sort(
            key=lambda row: (
                -float(row["max_threat_level_score"]),
                -int(row["evidence_total"]),
                str(row["assessment_name"]).lower(),
            )
        )

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "rollup_last_generated_at": rollup_generated_at,
            "source_uri": source_uri,
            "source_scope": scope,
            "window": {
                "days": window_days,
                "since": current_since.isoformat(),
                "until": current_until.isoformat(),
            },
            "docs_total": docs_total,
            "assessments_total": len(by_assessment),
            "level_distribution": {
                str(level): int(level_distribution.get(level, 0))
                for level in range(1, 6)
            },
            "attribution_distribution": {
                state: int(attribution_distribution.get(state, 0))
                for state in self.CTI_ATTRIBUTION_STATES
            },
            "top_assessments": top_assessments[:10],
        }

    def get_cti_trends(
        self,
        *,
        days: int = 30,
        top_n: int = 10,
        group_by: str = "activity",
        source_uri: Optional[str] = None,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        top_n = max(1, min(int(top_n), 50))
        group_by = str(group_by or "activity").strip().lower()
        if group_by not in {"activity", "domain", "actor"}:
            group_by = "activity"

        window_days, current_since, current_until = self._daily_window_bounds(
            days=days,
            since=since,
            until=until,
        )
        previous_since = current_since - timedelta(days=window_days)
        scope = self._source_scope(source_uri)
        current_bucket_keys = [
            bucket.isoformat()
            for bucket in self._iter_day_starts(current_since, current_until)
        ]

        filters: List[Dict[str, Any]] = [
            {"term": {"metric_type": self.METRIC_TYPE_DAILY_CTI_ASSESSMENT}},
            {"term": {"source_scope": scope}},
            {"range": {"bucket_start": {"gte": previous_since.isoformat()}}},
            {"range": {"bucket_start": {"lt": current_until.isoformat()}}},
        ]
        hits = self._iter_search_hits(
            self.indices.metrics,
            query={"bool": {"filter": filters}},
            sort=[{"bucket_start": "asc"}, {"_id": "asc"}],
            size=1000,
        )

        grouped: Dict[str, Dict[str, Any]] = {}
        rollup_generated_at: Optional[str] = None
        for hit in hits:
            source = hit.get("_source") or {}
            bucket_start_raw = source.get("bucket_start")
            if not bucket_start_raw:
                continue
            bucket_ts = _parse_datetime(bucket_start_raw)
            if bucket_ts.tzinfo is None:
                bucket_ts = bucket_ts.replace(tzinfo=timezone.utc)
            else:
                bucket_ts = bucket_ts.astimezone(timezone.utc)
            bucket_key = bucket_ts.replace(
                hour=0, minute=0, second=0, microsecond=0
            ).isoformat()

            if group_by == "domain":
                key = str(source.get("domain_key") or "")
                label = str(source.get("domain_name") or key)
            elif group_by == "actor":
                key = str(source.get("actor_id") or "")
                label = str(source.get("actor_name") or key)
            else:
                key = str(source.get("assessment_id") or "")
                label = str(source.get("assessment_name") or key)
            if not key:
                continue

            score = float(source.get("threat_level_score") or 0.0)
            evidence = int(source.get("evidence_count") or 0)
            state = str(source.get("attribution_state") or "unknown")
            if state not in self.CTI_ATTRIBUTION_STATES:
                state = "unknown"

            row = grouped.setdefault(
                key,
                {
                    "id": key,
                    "label": label,
                    "current_score_sum": 0.0,
                    "previous_score_sum": 0.0,
                    "current_evidence": 0,
                    "previous_evidence": 0,
                    "history_scores": Counter(),
                    "history_counts": Counter(),
                    "history_evidence": Counter(),
                    "state_counts": Counter(),
                },
            )

            if previous_since <= bucket_ts < current_since:
                row["previous_score_sum"] = float(row["previous_score_sum"]) + score
                row["previous_evidence"] = int(row["previous_evidence"]) + evidence
            if current_since <= bucket_ts < current_until:
                row["current_score_sum"] = float(row["current_score_sum"]) + score
                row["current_evidence"] = int(row["current_evidence"]) + evidence
                row["history_scores"][bucket_key] += score
                row["history_counts"][bucket_key] += 1
                row["history_evidence"][bucket_key] += evidence
                row["state_counts"][state] += 1

            latest_rollup = source.get("rollup_generated_at")
            if latest_rollup and (
                not rollup_generated_at or str(latest_rollup) > str(rollup_generated_at)
            ):
                rollup_generated_at = str(latest_rollup)

        items: List[Dict[str, Any]] = []
        for row in grouped.values():
            current_avg_score = self._clamp_score(
                float(row["current_score_sum"]) / float(max(window_days, 1))
            )
            previous_avg_score = self._clamp_score(
                float(row["previous_score_sum"]) / float(max(window_days, 1))
            )
            if current_avg_score <= 0.0 and int(row["current_evidence"]) <= 0:
                continue
            delta_score = current_avg_score - previous_avg_score
            trend_score = delta_score / max(previous_avg_score, 0.0001)
            history = []
            for key in current_bucket_keys:
                day_count = int(row["history_counts"].get(key, 0))
                day_score_sum = float(row["history_scores"].get(key, 0.0))
                day_avg_score = (
                    self._clamp_score(day_score_sum / float(day_count))
                    if day_count > 0
                    else 0.0
                )
                history.append(
                    {
                        "bucket_start": key,
                        "threat_level_score": round(day_avg_score, 4),
                        "evidence_count": int(row["history_evidence"].get(key, 0)),
                    }
                )
            state_counts = row.get("state_counts", Counter())
            dominant_state = "unknown"
            if state_counts:
                dominant_state = str(
                    max(
                        state_counts.items(),
                        key=lambda kv: (int(kv[1]), kv[0]),
                    )[0]
                )
            items.append(
                {
                    "id": row["id"],
                    "label": row["label"],
                    "group_by": group_by,
                    "current_threat_level_score": round(current_avg_score, 4),
                    "previous_threat_level_score": round(previous_avg_score, 4),
                    "delta_threat_level_score": round(delta_score, 4),
                    "trend_score": round(trend_score, 4),
                    "threat_level": self._score_to_level(current_avg_score),
                    "attribution_state": dominant_state,
                    "current_evidence": int(row["current_evidence"]),
                    "previous_evidence": int(row["previous_evidence"]),
                    "delta_evidence": int(row["current_evidence"])
                    - int(row["previous_evidence"]),
                    "history": history,
                }
            )

        items.sort(
            key=lambda item: (
                -float(item["delta_threat_level_score"]),
                -float(item["current_threat_level_score"]),
                -int(item["current_evidence"]),
                str(item["label"]).lower(),
            )
        )

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "rollup_last_generated_at": rollup_generated_at,
            "source_uri": source_uri,
            "source_scope": scope,
            "group_by": group_by,
            "window": {
                "days": window_days,
                "since": current_since.isoformat(),
                "until": current_until.isoformat(),
            },
            "compare_window": {
                "days": window_days,
                "since": previous_since.isoformat(),
                "until": current_since.isoformat(),
            },
            "items": items[:top_n],
        }

    def get_pir_trending_summary(
        self,
        *,
        days: int = 7,
        top_n: int = 10,
        source_uri: Optional[str] = None,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        top_n = max(1, min(int(top_n), 50))
        window_days, current_since, current_until = self._daily_window_bounds(
            days=days,
            since=since,
            until=until,
        )
        previous_since = current_since - timedelta(days=window_days)
        scope = self._source_scope(source_uri)

        # Use composite aggregation to build per-entity stats in ES
        # instead of downloading all docs.
        filters: List[Dict[str, Any]] = [
            {"term": {"metric_type": self.METRIC_TYPE_DAILY_PIR_ENTITY}},
            {"term": {"source_scope": scope}},
            {"range": {"bucket_start": {"gte": previous_since.isoformat()}}},
            {"range": {"bucket_start": {"lt": current_until.isoformat()}}},
        ]
        query = {"bool": {"filter": filters}}

        aggregated: Dict[str, Dict[str, Dict[str, Any]]] = {
            entity_type: {} for entity_type in self.PIR_ENTITY_TYPES
        }
        rollup_generated_at: Optional[str] = None

        # Paginate with composite agg: group by (entity_type, entity_id)
        after: Optional[Dict[str, Any]] = None
        while True:
            composite_body: Dict[str, Any] = {
                "sources": [
                    {"entity_type": {"terms": {"field": "entity_type"}}},
                    {"entity_id": {"terms": {"field": "entity_id"}}},
                ],
                "size": 2000,
            }
            if after:
                composite_body["after"] = after

            response = self.client.search(
                index=self.indices.metrics,
                query=query,
                size=0,
                aggs={
                    "by_entity": {
                        "composite": composite_body,
                        "aggs": {
                            "current_evidence": {
                                "filter": {
                                    "range": {
                                        "bucket_start": {
                                            "gte": current_since.isoformat(),
                                            "lt": current_until.isoformat(),
                                        }
                                    }
                                },
                                "aggs": {
                                    "total": {"sum": {"field": "evidence_count"}},
                                    "relations": {"sum": {"field": "relation_count"}},
                                    "daily": {
                                        "date_histogram": {
                                            "field": "bucket_start",
                                            "calendar_interval": "day",
                                        },
                                        "aggs": {
                                            "evidence": {
                                                "sum": {"field": "evidence_count"}
                                            }
                                        },
                                    },
                                },
                            },
                            "previous_evidence": {
                                "filter": {
                                    "range": {
                                        "bucket_start": {
                                            "gte": previous_since.isoformat(),
                                            "lt": current_since.isoformat(),
                                        }
                                    }
                                },
                                "aggs": {"total": {"sum": {"field": "evidence_count"}}},
                            },
                            "entity_name": {
                                "top_hits": {
                                    "size": 1,
                                    "_source": ["entity_name"],
                                    "sort": [{"bucket_start": "desc"}],
                                }
                            },
                            "latest_rollup": {"max": {"field": "rollup_generated_at"}},
                        },
                    }
                },
            )

            comp_agg = response.get("aggregations", {}).get("by_entity", {})
            buckets = comp_agg.get("buckets", [])
            if not buckets:
                break

            for bucket in buckets:
                entity_type = str(bucket["key"]["entity_type"])
                entity_id = str(bucket["key"]["entity_id"])
                if entity_type not in aggregated or not entity_id:
                    continue

                current_agg = bucket.get("current_evidence", {})
                previous_agg = bucket.get("previous_evidence", {})

                current_ev = int(current_agg.get("total", {}).get("value", 0))
                previous_ev = int(previous_agg.get("total", {}).get("value", 0))
                relation_count = int(current_agg.get("relations", {}).get("value", 0))

                # Extract entity name from top_hits
                name_hits = (
                    bucket.get("entity_name", {}).get("hits", {}).get("hits", [])
                )
                entity_name = entity_id
                if name_hits:
                    entity_name = str(
                        name_hits[0].get("_source", {}).get("entity_name", entity_id)
                    )

                # Build daily history from date_histogram
                history_counts: Counter = Counter()
                for day_bucket in current_agg.get("daily", {}).get("buckets", []):
                    ts = _parse_datetime(day_bucket.get("key_as_string"))
                    bucket_key = ts.replace(
                        hour=0, minute=0, second=0, microsecond=0
                    ).isoformat()
                    history_counts[bucket_key] += int(
                        day_bucket.get("evidence", {}).get("value", 0)
                    )

                # Track latest rollup timestamp
                latest_rollup = bucket.get("latest_rollup", {}).get("value_as_string")
                if latest_rollup and (
                    not rollup_generated_at
                    or str(latest_rollup) > str(rollup_generated_at)
                ):
                    rollup_generated_at = str(latest_rollup)

                aggregated[entity_type][entity_id] = {
                    "entity_id": entity_id,
                    "name": entity_name,
                    "type": entity_type,
                    "current_evidence": current_ev,
                    "previous_evidence": previous_ev,
                    "relation_count_current": relation_count,
                    "history_counts": history_counts,
                }

            after = buckets[-1]["key"]
            if len(buckets) < 2000:
                break

        current_buckets = self._iter_day_starts(current_since, current_until)
        current_bucket_keys = [bucket.isoformat() for bucket in current_buckets]

        def _build_question(entity_type: str, question: str) -> Dict[str, Any]:
            items = []
            for entity in aggregated.get(entity_type, {}).values():
                current_evidence = int(entity["current_evidence"])
                if current_evidence <= 0:
                    continue
                previous_evidence = int(entity["previous_evidence"])
                delta = current_evidence - previous_evidence
                trend_score = delta / max(previous_evidence, 1)
                history = [
                    {
                        "bucket_start": key,
                        "evidence_count": int(entity["history_counts"].get(key, 0)),
                    }
                    for key in current_bucket_keys
                ]
                items.append(
                    {
                        "entity_id": entity["entity_id"],
                        "name": entity["name"],
                        "type": entity["type"],
                        "current_evidence": current_evidence,
                        "previous_evidence": previous_evidence,
                        "delta_evidence": delta,
                        "trend_score": trend_score,
                        "relation_count_current": int(entity["relation_count_current"]),
                        "top_predicates": [],
                        "history": history,
                    }
                )

            items.sort(
                key=lambda item: (
                    -int(item["delta_evidence"]),
                    -int(item["current_evidence"]),
                    str(item["name"]).lower(),
                )
            )
            items = items[:top_n]

            return {
                "id": f"{entity_type}_trending",
                "question": question,
                "entity_type": entity_type,
                "item_count": len(items),
                "items": items,
            }

        generated_at = datetime.now(timezone.utc).isoformat()
        return {
            "generated_at": generated_at,
            "rollup_last_generated_at": rollup_generated_at,
            "source_uri": source_uri,
            "source_scope": scope,
            "window": {
                "days": window_days,
                "since": current_since.isoformat(),
                "until": current_until.isoformat(),
            },
            "compare_window": {
                "days": window_days,
                "since": previous_since.isoformat(),
                "until": current_since.isoformat(),
            },
            "questions": [
                _build_question(entity_type, question)
                for entity_type, question in self.PIR_QUESTIONS.items()
            ],
        }

    def get_rollup_overview(
        self,
        days: int = 30,
        source_uri: Optional[str] = None,
    ) -> Dict[str, Any]:
        days = max(int(days), 1)
        since = datetime.utcnow() - timedelta(days=days)
        scope = self._source_scope(source_uri)
        filters = [
            {"term": {"metric_type": self.METRIC_TYPE_DAILY_THREAT_ACTOR}},
            {"term": {"source_scope": scope}},
            {"range": {"bucket_start": {"gte": since.isoformat()}}},
        ]
        response = self.client.search(
            index=self.indices.metrics,
            query={"bool": {"filter": filters}},
            size=1,
            sort=[
                {"bucket_start": "desc"},
                {"evidence_count": "desc"},
                {"entity_name": "asc"},
            ],
            aggs={
                "active_actors": {"cardinality": {"field": "entity_id"}},
                "evidence_total": {"sum": {"field": "evidence_count"}},
                "latest_bucket": {"max": {"field": "bucket_start"}},
                "latest_rollup": {"max": {"field": "rollup_generated_at"}},
            },
        )
        hits = response.get("hits", {}).get("hits", [])
        top_actor = None
        if hits:
            top = hits[0]["_source"]
            top_actor = {
                "entity_id": top.get("entity_id"),
                "entity_name": top.get("entity_name"),
                "bucket_start": top.get("bucket_start"),
                "evidence_count": int(top.get("evidence_count", 0)),
                "relation_count": int(top.get("relation_count", 0)),
            }
        aggs = response.get("aggregations", {})
        return {
            "metric_type": self.METRIC_TYPE_DAILY_THREAT_ACTOR,
            "source_scope": scope,
            "days": days,
            "active_actors": int(aggs.get("active_actors", {}).get("value") or 0),
            "evidence_total": float(aggs.get("evidence_total", {}).get("value") or 0.0),
            "latest_bucket": aggs.get("latest_bucket", {}).get("value_as_string"),
            "last_rollup_at": aggs.get("latest_rollup", {}).get("value_as_string"),
            "top_actor": top_actor,
        }
