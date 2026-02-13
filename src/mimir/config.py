from __future__ import annotations

import os
from dataclasses import dataclass
from typing import List


def _env_bool(name: str, default: str = "0") -> bool:
    value = os.getenv(name, default)
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    ollama_base_url: str = os.getenv(
        "OLLAMA_BASE_URL", "http://host.docker.internal:11434"
    )
    ollama_model: str = os.getenv("OLLAMA_MODEL", "phi4")
    prompt_version: str = os.getenv("PROMPT_VERSION", "v1")
    chunk_size: int = int(os.getenv("CHUNK_SIZE", "1200"))
    chunk_overlap: int = int(os.getenv("CHUNK_OVERLAP", "200"))
    elastic_hosts: str = os.getenv("ELASTICSEARCH_HOST", "http://127.0.0.1:9200")
    elastic_user: str = os.getenv("ELASTICSEARCH_USER", "")
    elastic_password: str = os.getenv("ELASTICSEARCH_PASSWORD", "")
    elastic_index_prefix: str = os.getenv("ELASTICSEARCH_INDEX_PREFIX", "mimir")
    elastic_verify_certs: bool = _env_bool("ELASTICSEARCH_VERIFY_CERTS", "1")
    log_level: str = os.getenv("LOG_LEVEL", "INFO")
    mimir_api_base_url: str = os.getenv(
        "MIMIR_API_BASE_URL",
        os.getenv("WELLSPRING_API_BASE_URL", ""),
    )
    query_max_nodes: int = int(os.getenv("QUERY_MAX_NODES", "400"))
    query_max_edges: int = int(os.getenv("QUERY_MAX_EDGES", "1200"))
    enable_cooccurrence: bool = os.getenv("ENABLE_COOCCURRENCE", "0") == "1"
    cooccurrence_max_entities: int = int(os.getenv("CO_OCCURRENCE_MAX_ENTITIES", "25"))
    enable_inference: bool = os.getenv("ENABLE_INFERENCE", "0") == "1"
    max_chunks_per_run: int = int(os.getenv("MAX_CHUNKS_PER_RUN", "50"))
    metrics_rollup_enabled: bool = os.getenv("METRICS_ROLLUP_ENABLED", "1") == "1"
    metrics_rollup_interval_seconds: int = int(
        os.getenv("METRICS_ROLLUP_INTERVAL_SECONDS", "900")
    )
    metrics_rollup_lookback_days: int = int(
        os.getenv("METRICS_ROLLUP_LOOKBACK_DAYS", "365")
    )
    metrics_rollup_min_confidence: float = float(
        os.getenv("METRICS_ROLLUP_MIN_CONFIDENCE", "0.0")
    )
    metrics_rollup_stale_seconds: int = int(
        os.getenv("METRICS_ROLLUP_STALE_SECONDS", "0")
    )
    cti_rollup_enabled: bool = _env_bool("CTI_ROLLUP_ENABLED", "1")
    cti_rollup_lookback_days: int = int(os.getenv("CTI_ROLLUP_LOOKBACK_DAYS", "365"))
    cti_decay_half_life_days: int = int(os.getenv("CTI_DECAY_HALF_LIFE_DAYS", "14"))
    cti_level_thresholds: str = os.getenv("CTI_LEVEL_THRESHOLDS", "0.2,0.4,0.6,0.8")
    opencti_url: str = os.getenv("OPENCTI_URL", "")
    opencti_token: str = os.getenv("OPENCTI_TOKEN", "")
    elastic_connector_enabled: bool = _env_bool(
        "ELASTIC_CONNECTOR_ENABLED",
        os.getenv("ELASTICSEARCH_ENABLED", "1"),
    )
    elastic_connector_hosts: str = os.getenv(
        "ELASTIC_CONNECTOR_HOSTS",
        os.getenv(
            "ELASTICSEARCH_URL",
            os.getenv("ELASTICSEARCH_HOST", "http://127.0.0.1:9200"),
        ),
    )
    elastic_connector_user: str = os.getenv(
        "ELASTIC_CONNECTOR_USER",
        os.getenv(
            "ELASTICSEARCH_USERNAME",
            os.getenv("ELASTICSEARCH_USER", ""),
        ),
    )
    elastic_connector_password: str = os.getenv(
        "ELASTIC_CONNECTOR_PASSWORD",
        os.getenv("ELASTICSEARCH_PASSWORD", ""),
    )
    elastic_connector_verify_certs: bool = _env_bool(
        "ELASTIC_CONNECTOR_VERIFY_CERTS",
        os.getenv(
            "ELASTICSEARCH_VERIFY_TLS",
            os.getenv("ELASTICSEARCH_VERIFY_CERTS", "1"),
        ),
    )
    elastic_connector_timeout_seconds: float = float(
        os.getenv(
            "ELASTIC_CONNECTOR_TIMEOUT",
            os.getenv("ELASTICSEARCH_TIMEOUT", "60"),
        )
    )
    elastic_connector_indices: str = os.getenv(
        "ELASTIC_CONNECTOR_INDICES",
        os.getenv("ELASTICSEARCH_INDEX", "feedly_news"),
    )
    elastic_connector_page_size: int = int(
        os.getenv(
            "ELASTIC_CONNECTOR_PAGE_SIZE",
            os.getenv("ELASTICSEARCH_BATCH_SIZE", "200"),
        )
    )
    elastic_connector_lookback_minutes: int = int(
        os.getenv("ELASTIC_CONNECTOR_LOOKBACK_MINUTES", "180")
    )
    elastic_connector_min_text_chars: int = int(
        os.getenv("ELASTIC_CONNECTOR_MIN_TEXT_CHARS", "50")
    )
    elastic_connector_strip_html: bool = _env_bool("ELASTIC_CONNECTOR_STRIP_HTML", "1")
    elastic_connector_normalize_whitespace: bool = _env_bool(
        "ELASTIC_CONNECTOR_NORMALIZE_WHITESPACE",
        "1",
    )
    elastic_connector_title_fields: str = os.getenv(
        "ELASTIC_CONNECTOR_TITLE_FIELDS", "title,headline,name"
    )
    elastic_connector_text_fields: str = os.getenv(
        "ELASTIC_CONNECTOR_TEXT_FIELDS",
        "content,text,summary,description,body,full_text",
    )
    elastic_connector_url_fields: str = os.getenv(
        "ELASTIC_CONNECTOR_URL_FIELDS",
        "url,link,origin_url",
    )
    elastic_connector_timestamp_fields: str = os.getenv(
        "ELASTIC_CONNECTOR_TIMESTAMP_FIELDS",
        "@timestamp,published,published_at,updated_at,created_at,timestamp",
    )
    watched_folders: str = os.getenv("WATCHED_FOLDERS", "/data/documents")
    sync_interval_minutes: int = int(os.getenv("SYNC_INTERVAL_MINUTES", "30"))
    sync_lookback_minutes: int = int(os.getenv("SYNC_LOOKBACK_MINUTES", "60"))

    # ── Worker-specific settings ─────────────────────────────
    # LLM extraction worker
    llm_worker_concurrency: int = int(os.getenv("LLM_WORKER_CONCURRENCY", "3"))
    llm_worker_poll_seconds: int = int(os.getenv("LLM_WORKER_POLL_SECONDS", "2"))
    max_pending_age_days: int = int(os.getenv("MAX_PENDING_AGE_DAYS", "14"))

    # Feedly connector worker
    feedly_worker_interval_minutes: int = int(
        os.getenv(
            "FEEDLY_WORKER_INTERVAL_MINUTES", os.getenv("SYNC_INTERVAL_MINUTES", "30")
        )
    )
    feedly_queue_for_llm: bool = _env_bool("FEEDLY_QUEUE_FOR_LLM", "0")

    # OpenCTI connector worker
    opencti_worker_interval_minutes: int = int(
        os.getenv(
            "OPENCTI_WORKER_INTERVAL_MINUTES", os.getenv("SYNC_INTERVAL_MINUTES", "30")
        )
    )

    # Elasticsearch source worker
    elastic_worker_interval_minutes: int = int(
        os.getenv(
            "ELASTIC_WORKER_INTERVAL_MINUTES", os.getenv("SYNC_INTERVAL_MINUTES", "30")
        )
    )
    elastic_worker_exclude_indices: str = os.getenv(
        "ELASTIC_WORKER_EXCLUDE_INDICES", "feedly_news"
    )

    @property
    def elastic_worker_exclude_indices_list(self) -> List[str]:
        return [
            idx.strip()
            for idx in self.elastic_worker_exclude_indices.split(",")
            if idx.strip()
        ]

    @property
    def elastic_hosts_list(self) -> List[str]:
        return [host.strip() for host in self.elastic_hosts.split(",") if host.strip()]

    @property
    def elastic_connector_hosts_list(self) -> List[str]:
        return [
            host.strip()
            for host in self.elastic_connector_hosts.split(",")
            if host.strip()
        ]

    @property
    def elastic_connector_indices_list(self) -> List[str]:
        return [
            index.strip()
            for index in self.elastic_connector_indices.split(",")
            if index.strip()
        ]

    @property
    def elastic_connector_title_fields_list(self) -> List[str]:
        return [
            field.strip()
            for field in self.elastic_connector_title_fields.split(",")
            if field.strip()
        ]

    @property
    def elastic_connector_text_fields_list(self) -> List[str]:
        return [
            field.strip()
            for field in self.elastic_connector_text_fields.split(",")
            if field.strip()
        ]

    @property
    def elastic_connector_url_fields_list(self) -> List[str]:
        return [
            field.strip()
            for field in self.elastic_connector_url_fields.split(",")
            if field.strip()
        ]

    @property
    def elastic_connector_timestamp_fields_list(self) -> List[str]:
        return [
            field.strip()
            for field in self.elastic_connector_timestamp_fields.split(",")
            if field.strip()
        ]

    @property
    def watched_folders_list(self) -> List[str]:
        return [d.strip() for d in self.watched_folders.split(",") if d.strip()]

    @property
    def cti_level_thresholds_list(self) -> List[float]:
        out: List[float] = []
        for value in self.cti_level_thresholds.split(","):
            value = value.strip()
            if not value:
                continue
            try:
                parsed = float(value)
            except ValueError:
                continue
            if 0.0 <= parsed <= 1.0:
                out.append(parsed)
        out = sorted(set(out))
        if len(out) >= 4:
            return out[:4]
        return [0.2, 0.4, 0.6, 0.8]


def get_settings() -> Settings:
    return Settings()
