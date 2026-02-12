from __future__ import annotations

from dataclasses import dataclass
import os
from typing import List


def _env_bool(name: str, default: str = "0") -> bool:
    value = os.getenv(name, default)
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    ollama_base_url: str = os.getenv("OLLAMA_BASE_URL", "http://host.docker.internal:11434")
    ollama_model: str = os.getenv("OLLAMA_MODEL", "phi4")
    prompt_version: str = os.getenv("PROMPT_VERSION", "v1")
    chunk_size: int = int(os.getenv("CHUNK_SIZE", "1200"))
    chunk_overlap: int = int(os.getenv("CHUNK_OVERLAP", "200"))
    elastic_hosts: str = os.getenv("ELASTICSEARCH_HOST", "http://127.0.0.1:9200")
    elastic_user: str = os.getenv("ELASTICSEARCH_USER", "")
    elastic_password: str = os.getenv("ELASTICSEARCH_PASSWORD", "")
    elastic_index_prefix: str = os.getenv("ELASTICSEARCH_INDEX_PREFIX", "wellspring")
    elastic_verify_certs: bool = _env_bool("ELASTICSEARCH_VERIFY_CERTS", "1")
    log_level: str = os.getenv("LOG_LEVEL", "INFO")
    enable_cooccurrence: bool = os.getenv("ENABLE_COOCCURRENCE", "0") == "1"
    cooccurrence_max_entities: int = int(os.getenv("CO_OCCURRENCE_MAX_ENTITIES", "25"))
    enable_inference: bool = os.getenv("ENABLE_INFERENCE", "0") == "1"
    max_chunks_per_run: int = int(os.getenv("MAX_CHUNKS_PER_RUN", "50"))
    metrics_rollup_enabled: bool = os.getenv("METRICS_ROLLUP_ENABLED", "1") == "1"
    metrics_rollup_interval_seconds: int = int(os.getenv("METRICS_ROLLUP_INTERVAL_SECONDS", "900"))
    metrics_rollup_lookback_days: int = int(os.getenv("METRICS_ROLLUP_LOOKBACK_DAYS", "365"))
    metrics_rollup_min_confidence: float = float(os.getenv("METRICS_ROLLUP_MIN_CONFIDENCE", "0.0"))
    metrics_rollup_stale_seconds: int = int(os.getenv("METRICS_ROLLUP_STALE_SECONDS", "0"))
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
    elastic_connector_lookback_minutes: int = int(os.getenv("ELASTIC_CONNECTOR_LOOKBACK_MINUTES", "180"))
    elastic_connector_min_text_chars: int = int(os.getenv("ELASTIC_CONNECTOR_MIN_TEXT_CHARS", "50"))
    elastic_connector_strip_html: bool = _env_bool("ELASTIC_CONNECTOR_STRIP_HTML", "1")
    elastic_connector_normalize_whitespace: bool = _env_bool(
        "ELASTIC_CONNECTOR_NORMALIZE_WHITESPACE",
        "1",
    )
    elastic_connector_title_fields: str = os.getenv("ELASTIC_CONNECTOR_TITLE_FIELDS", "title,headline,name")
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

    @property
    def elastic_hosts_list(self) -> List[str]:
        return [host.strip() for host in self.elastic_hosts.split(",") if host.strip()]

    @property
    def elastic_connector_hosts_list(self) -> List[str]:
        return [host.strip() for host in self.elastic_connector_hosts.split(",") if host.strip()]

    @property
    def elastic_connector_indices_list(self) -> List[str]:
        return [index.strip() for index in self.elastic_connector_indices.split(",") if index.strip()]

    @property
    def elastic_connector_title_fields_list(self) -> List[str]:
        return [field.strip() for field in self.elastic_connector_title_fields.split(",") if field.strip()]

    @property
    def elastic_connector_text_fields_list(self) -> List[str]:
        return [field.strip() for field in self.elastic_connector_text_fields.split(",") if field.strip()]

    @property
    def elastic_connector_url_fields_list(self) -> List[str]:
        return [field.strip() for field in self.elastic_connector_url_fields.split(",") if field.strip()]

    @property
    def elastic_connector_timestamp_fields_list(self) -> List[str]:
        return [field.strip() for field in self.elastic_connector_timestamp_fields.split(",") if field.strip()]

    @property
    def watched_folders_list(self) -> List[str]:
        return [d.strip() for d in self.watched_folders.split(",") if d.strip()]


def get_settings() -> Settings:
    return Settings()
