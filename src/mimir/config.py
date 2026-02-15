from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Dict, List


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
    mimir_api_base_url: str = os.getenv("MIMIR_API_BASE_URL", "")
    api_token: str = os.getenv("MIMIR_API_TOKEN", "")
    auth_disabled: bool = _env_bool("MIMIR_AUTH_DISABLED", "0")
    allow_localhost_without_token: bool = _env_bool(
        "MIMIR_ALLOW_LOCALHOST_WITHOUT_TOKEN", "1"
    )
    expose_local_paths: bool = _env_bool("MIMIR_EXPOSE_LOCAL_PATHS", "0")
    search_query_max_length: int = int(os.getenv("SEARCH_QUERY_MAX_LENGTH", "120"))
    query_max_nodes: int = int(os.getenv("QUERY_MAX_NODES", "400"))
    query_max_edges: int = int(os.getenv("QUERY_MAX_EDGES", "1200"))
    enable_cooccurrence: bool = _env_bool("ENABLE_COOCCURRENCE", "0")
    cooccurrence_max_entities: int = int(os.getenv("CO_OCCURRENCE_MAX_ENTITIES", "25"))
    enable_inference: bool = _env_bool("ENABLE_INFERENCE", "0")
    max_chunks_per_run: int = int(os.getenv("MAX_CHUNKS_PER_RUN", "50"))
    metrics_rollup_enabled: bool = _env_bool("METRICS_ROLLUP_ENABLED", "1")
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
    cti_source_confidence_rules: str = os.getenv(
        "CTI_SOURCE_CONFIDENCE_RULES",
        (
            "opencti=0.90,malware=0.88,gvm=0.88,watcher=0.80,feedly=0.78,elasticsearch=0.72,"
            "stix=0.75,upload=0.55,file=0.50,unknown=0.45"
        ),
    )
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
    worker_heartbeat_dir: str = os.getenv(
        "WORKER_HEARTBEAT_DIR", "/data/worker-heartbeats"
    )

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

    # RSS threat feed worker (public/no-license feeds)
    rss_worker_enabled: bool = _env_bool("RSS_WORKER_ENABLED", "0")
    rss_worker_interval_minutes: int = int(
        os.getenv(
            "RSS_WORKER_INTERVAL_MINUTES", os.getenv("SYNC_INTERVAL_MINUTES", "30")
        )
    )
    rss_worker_feeds: str = os.getenv(
        "RSS_WORKER_FEEDS",
        "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    )
    rss_worker_lookback_hours: int = int(os.getenv("RSS_WORKER_LOOKBACK_HOURS", "168"))
    rss_worker_max_items_per_feed: int = int(
        os.getenv("RSS_WORKER_MAX_ITEMS_PER_FEED", "200")
    )
    rss_worker_min_text_chars: int = int(os.getenv("RSS_WORKER_MIN_TEXT_CHARS", "80"))
    rss_worker_timeout_seconds: float = float(
        os.getenv("RSS_WORKER_TIMEOUT_SECONDS", "20")
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

    # Malware worker
    malware_worker_enabled: bool = _env_bool("MALWARE_WORKER_ENABLED", "1")
    malware_worker_interval_minutes: int = int(
        os.getenv(
            "MALWARE_WORKER_INTERVAL_MINUTES",
            os.getenv("SYNC_INTERVAL_MINUTES", "30"),
        )
    )
    malware_worker_indices: str = os.getenv(
        "MALWARE_WORKER_INDICES", "mwdb-openrelik,dailymalwarefeed-*"
    )
    malware_worker_lookback_minutes: int = int(
        os.getenv("MALWARE_WORKER_LOOKBACK_MINUTES", "180")
    )
    malware_worker_max_per_index: int = int(
        os.getenv("MALWARE_WORKER_MAX_PER_INDEX", "500")
    )

    # GVM (Greenbone Vulnerability Management) connector
    gvm_worker_enabled: bool = _env_bool("GVM_WORKER_ENABLED", "0")
    gvm_worker_interval_minutes: int = int(
        os.getenv(
            "GVM_WORKER_INTERVAL_MINUTES",
            os.getenv("SYNC_INTERVAL_MINUTES", "30"),
        )
    )
    gvm_worker_lookback_minutes: int = int(
        os.getenv("GVM_WORKER_LOOKBACK_MINUTES", "180")
    )
    gvm_connection_type: str = os.getenv("GVM_CONNECTION_TYPE", "unix")
    gvm_socket_path: str = os.getenv("GVM_SOCKET_PATH", "/run/gvmd/gvmd.sock")
    gvm_host: str = os.getenv("GVM_HOST", "127.0.0.1")
    gvm_port: int = int(os.getenv("GVM_PORT", "9390"))
    gvm_username: str = os.getenv("GVM_USERNAME", "admin")
    gvm_password: str = os.getenv("GVM_PASSWORD", "admin")
    gvm_max_results: int = int(os.getenv("GVM_MAX_RESULTS", "500"))
    gvm_min_qod: int = int(os.getenv("GVM_MIN_QOD", "30"))
    gvm_ca_cert: str = os.getenv("GVM_CA_CERT", "")

    # Watcher (Thales CERT threat intelligence platform)
    watcher_worker_enabled: bool = _env_bool("WATCHER_WORKER_ENABLED", "0")
    watcher_worker_interval_minutes: int = int(
        os.getenv(
            "WATCHER_WORKER_INTERVAL_MINUTES",
            os.getenv("SYNC_INTERVAL_MINUTES", "30"),
        )
    )
    watcher_worker_lookback_minutes: int = int(
        os.getenv("WATCHER_WORKER_LOOKBACK_MINUTES", "180")
    )
    watcher_base_url: str = os.getenv("WATCHER_BASE_URL", "http://127.0.0.1:9002")
    watcher_api_token: str = os.getenv("WATCHER_API_TOKEN", "")
    watcher_verify_tls: bool = _env_bool("WATCHER_VERIFY_TLS", "1")
    watcher_timeout_seconds: float = float(os.getenv("WATCHER_TIMEOUT_SECONDS", "30"))
    watcher_page_size: int = int(os.getenv("WATCHER_PAGE_SIZE", "200"))
    watcher_pull_trendy_words: bool = _env_bool("WATCHER_PULL_TRENDY_WORDS", "1")
    watcher_pull_data_leaks: bool = _env_bool("WATCHER_PULL_DATA_LEAKS", "1")
    watcher_pull_dns_twisted: bool = _env_bool("WATCHER_PULL_DNS_TWISTED", "1")
    watcher_pull_site_monitoring: bool = _env_bool("WATCHER_PULL_SITE_MONITORING", "1")
    watcher_min_trendy_score: float = float(
        os.getenv("WATCHER_MIN_TRENDY_SCORE", "0.0")
    )
    watcher_min_trendy_occurrences: int = int(
        os.getenv("WATCHER_MIN_TRENDY_OCCURRENCES", "1")
    )

    # AIKG JSON import (subject-predicate-object arrays)
    aikg_import_include_inferred: bool = _env_bool("AIKG_IMPORT_INCLUDE_INFERRED", "0")
    aikg_import_min_inferred_confidence: float = float(
        os.getenv("AIKG_IMPORT_MIN_INFERRED_CONFIDENCE", "0.60")
    )
    aikg_import_allow_via_predicates: bool = _env_bool(
        "AIKG_IMPORT_ALLOW_VIA_PREDICATES", "0"
    )

    # Data ingestion limits
    max_document_size_mb: int = int(os.getenv("MAX_DOCUMENT_SIZE_MB", "100"))
    max_total_chars_per_run: int = int(os.getenv("MAX_TOTAL_CHARS_PER_RUN", "1000000"))

    # Elasticsearch retry policy
    es_retry_max_attempts: int = int(os.getenv("ES_RETRY_MAX_ATTEMPTS", "3"))
    es_retry_initial_delay_seconds: float = float(
        os.getenv("ES_RETRY_INITIAL_DELAY_SECONDS", "1.0")
    )

    # Timeouts
    ollama_timeout_seconds: float = float(os.getenv("OLLAMA_TIMEOUT_SECONDS", "300.0"))
    startup_health_check_timeout_seconds: float = float(
        os.getenv("STARTUP_HEALTH_CHECK_TIMEOUT_SECONDS", "30.0")
    )

    @property
    def elastic_worker_exclude_indices_list(self) -> List[str]:
        return [
            idx.strip()
            for idx in self.elastic_worker_exclude_indices.split(",")
            if idx.strip()
        ]

    @property
    def malware_worker_indices_list(self) -> List[str]:
        return [
            idx.strip() for idx in self.malware_worker_indices.split(",") if idx.strip()
        ]

    @property
    def rss_worker_feeds_list(self) -> List[str]:
        return [
            feed.strip() for feed in self.rss_worker_feeds.split(",") if feed.strip()
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

    @property
    def cti_source_confidence_rules_map(self) -> Dict[str, float]:
        default_rules: Dict[str, float] = {
            "opencti": 0.90,
            "malware": 0.88,
            "gvm": 0.88,
            "watcher": 0.80,
            "feedly": 0.78,
            "elasticsearch": 0.72,
            "stix": 0.75,
            "upload": 0.55,
            "file": 0.50,
            "unknown": 0.45,
        }
        parsed_rules: Dict[str, float] = {}
        for token in self.cti_source_confidence_rules.split(","):
            token = token.strip()
            if not token or "=" not in token:
                continue
            key, value = token.split("=", 1)
            key = key.strip().lower()
            if not key:
                continue
            try:
                score = float(value.strip())
            except ValueError:
                continue
            parsed_rules[key] = max(0.0, min(score, 1.0))
        if not parsed_rules:
            return dict(default_rules)
        merged_rules = dict(default_rules)
        merged_rules.update(parsed_rules)
        if "unknown" not in merged_rules:
            merged_rules["unknown"] = default_rules["unknown"]
        return merged_rules


def get_settings() -> Settings:
    return Settings()


def validate_settings(settings: Settings) -> None:
    """Validate settings at startup and raise ValueError if issues found."""
    import logging

    logger = logging.getLogger(__name__)

    # Validate Elasticsearch hosts
    if not settings.elastic_hosts_list:
        raise ValueError(
            "ELASTICSEARCH_HOST not set or empty; at least one Elasticsearch host required"
        )

    # Validate worker concurrency
    if settings.llm_worker_concurrency < 1:
        raise ValueError(
            f"LLM_WORKER_CONCURRENCY must be >= 1, got {settings.llm_worker_concurrency}"
        )

    # Validate timeouts
    if settings.ollama_timeout_seconds <= 0:
        raise ValueError(
            f"OLLAMA_TIMEOUT_SECONDS must be > 0, got {settings.ollama_timeout_seconds}"
        )
    if settings.startup_health_check_timeout_seconds <= 0:
        raise ValueError(
            f"STARTUP_HEALTH_CHECK_TIMEOUT_SECONDS must be > 0, "
            f"got {settings.startup_health_check_timeout_seconds}"
        )

    # Validate document size limits
    if settings.max_document_size_mb <= 0:
        raise ValueError(
            f"MAX_DOCUMENT_SIZE_MB must be > 0, got {settings.max_document_size_mb}"
        )
    if settings.max_total_chars_per_run <= 0:
        raise ValueError(
            f"MAX_TOTAL_CHARS_PER_RUN must be > 0, got {settings.max_total_chars_per_run}"
        )

    # Validate retry policy
    if settings.es_retry_max_attempts < 0:
        raise ValueError(
            f"ES_RETRY_MAX_ATTEMPTS must be >= 0, got {settings.es_retry_max_attempts}"
        )
    if settings.es_retry_initial_delay_seconds <= 0:
        raise ValueError(
            f"ES_RETRY_INITIAL_DELAY_SECONDS must be > 0, "
            f"got {settings.es_retry_initial_delay_seconds}"
        )

    if settings.search_query_max_length < 8:
        raise ValueError(
            "SEARCH_QUERY_MAX_LENGTH must be >= 8, "
            f"got {settings.search_query_max_length}"
        )
    if settings.rss_worker_interval_minutes < 0:
        raise ValueError(
            "RSS_WORKER_INTERVAL_MINUTES must be >= 0, "
            f"got {settings.rss_worker_interval_minutes}"
        )
    if settings.rss_worker_lookback_hours < 0:
        raise ValueError(
            "RSS_WORKER_LOOKBACK_HOURS must be >= 0, "
            f"got {settings.rss_worker_lookback_hours}"
        )
    if settings.rss_worker_max_items_per_feed < 1:
        raise ValueError(
            "RSS_WORKER_MAX_ITEMS_PER_FEED must be >= 1, "
            f"got {settings.rss_worker_max_items_per_feed}"
        )
    if settings.rss_worker_min_text_chars < 1:
        raise ValueError(
            "RSS_WORKER_MIN_TEXT_CHARS must be >= 1, "
            f"got {settings.rss_worker_min_text_chars}"
        )
    if settings.rss_worker_timeout_seconds <= 0:
        raise ValueError(
            "RSS_WORKER_TIMEOUT_SECONDS must be > 0, "
            f"got {settings.rss_worker_timeout_seconds}"
        )
    if settings.gvm_worker_interval_minutes < 0:
        raise ValueError(
            "GVM_WORKER_INTERVAL_MINUTES must be >= 0, "
            f"got {settings.gvm_worker_interval_minutes}"
        )
    if settings.gvm_worker_lookback_minutes < 0:
        raise ValueError(
            "GVM_WORKER_LOOKBACK_MINUTES must be >= 0, "
            f"got {settings.gvm_worker_lookback_minutes}"
        )
    if settings.gvm_max_results < 1:
        raise ValueError(
            "GVM_MAX_RESULTS must be >= 1, " f"got {settings.gvm_max_results}"
        )
    if not (0 <= settings.gvm_min_qod <= 100):
        raise ValueError(
            "GVM_MIN_QOD must be between 0 and 100, " f"got {settings.gvm_min_qod}"
        )
    gvm_conn_type = settings.gvm_connection_type.strip().lower()
    if gvm_conn_type not in {"unix", "tls"}:
        raise ValueError(
            "GVM_CONNECTION_TYPE must be one of {'unix', 'tls'}, "
            f"got {settings.gvm_connection_type!r}"
        )
    if gvm_conn_type == "unix" and not settings.gvm_socket_path.strip():
        raise ValueError("GVM_SOCKET_PATH must be set when GVM_CONNECTION_TYPE='unix'")
    if gvm_conn_type == "tls":
        if not settings.gvm_host.strip():
            raise ValueError("GVM_HOST must be set when GVM_CONNECTION_TYPE='tls'")
        if settings.gvm_port <= 0 or settings.gvm_port > 65535:
            raise ValueError(
                "GVM_PORT must be between 1 and 65535, " f"got {settings.gvm_port}"
            )
    if settings.watcher_worker_interval_minutes < 0:
        raise ValueError(
            "WATCHER_WORKER_INTERVAL_MINUTES must be >= 0, "
            f"got {settings.watcher_worker_interval_minutes}"
        )
    if settings.watcher_worker_lookback_minutes < 0:
        raise ValueError(
            "WATCHER_WORKER_LOOKBACK_MINUTES must be >= 0, "
            f"got {settings.watcher_worker_lookback_minutes}"
        )
    if settings.watcher_timeout_seconds <= 0:
        raise ValueError(
            "WATCHER_TIMEOUT_SECONDS must be > 0, "
            f"got {settings.watcher_timeout_seconds}"
        )
    if settings.watcher_page_size < 1:
        raise ValueError(
            "WATCHER_PAGE_SIZE must be >= 1, " f"got {settings.watcher_page_size}"
        )
    if settings.watcher_min_trendy_score < 0:
        raise ValueError(
            "WATCHER_MIN_TRENDY_SCORE must be >= 0, "
            f"got {settings.watcher_min_trendy_score}"
        )
    if settings.watcher_min_trendy_occurrences < 1:
        raise ValueError(
            "WATCHER_MIN_TRENDY_OCCURRENCES must be >= 1, "
            f"got {settings.watcher_min_trendy_occurrences}"
        )
    if not (0.0 <= settings.aikg_import_min_inferred_confidence <= 1.0):
        raise ValueError(
            "AIKG_IMPORT_MIN_INFERRED_CONFIDENCE must be between 0.0 and 1.0, "
            f"got {settings.aikg_import_min_inferred_confidence}"
        )

    # Log resolved settings for debugging
    logger.info("Settings validated successfully")
    logger.debug(
        "Resolved settings: ollama_model=%s, chunk_size=%d, "
        "max_document_size_mb=%d, llm_concurrency=%d, es_hosts=%s",
        settings.ollama_model,
        settings.chunk_size,
        settings.max_document_size_mb,
        settings.llm_worker_concurrency,
        ",".join(settings.elastic_hosts_list),
    )
