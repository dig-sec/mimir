from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class Entity(BaseModel):
    id: str
    name: str
    type: Optional[str] = None
    aliases: List[str] = Field(default_factory=list)
    attrs: Dict[str, Any] = Field(default_factory=dict)


class Relation(BaseModel):
    id: str
    subject_id: str
    predicate: str
    object_id: str
    confidence: float = 0.5
    attrs: Dict[str, Any] = Field(default_factory=dict)


class Triple(BaseModel):
    subject: str
    predicate: str
    object: str
    confidence: float = 0.5


class Provenance(BaseModel):
    provenance_id: str
    source_uri: str
    chunk_id: str
    start_offset: int
    end_offset: int
    snippet: str
    extraction_run_id: str
    model: str
    prompt_version: str
    timestamp: datetime


class ExtractionRun(BaseModel):
    run_id: str
    started_at: datetime
    model: str
    prompt_version: str
    params: Dict[str, Any]
    status: str
    error: Optional[str] = None


class Chunk(BaseModel):
    chunk_id: str
    source_uri: str
    start_offset: int
    end_offset: int
    text: str


class IngestRequest(BaseModel):
    source_uri: str
    text: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class IngestResponse(BaseModel):
    run_id: str
    status: str


class QueryRequest(BaseModel):
    seed_id: Optional[str] = None
    seed_name: Optional[str] = None
    depth: int = 1
    min_confidence: float = 0.0
    source_uri: Optional[str] = None
    since: Optional[datetime] = None
    until: Optional[datetime] = None


class SubgraphNode(BaseModel):
    id: str
    name: str
    type: Optional[str] = None


class SubgraphEdge(BaseModel):
    id: str
    subject_id: str
    predicate: str
    object_id: str
    confidence: float
    attrs: Dict[str, Any] = Field(default_factory=dict)


class Subgraph(BaseModel):
    nodes: List[SubgraphNode]
    edges: List[SubgraphEdge]


class ExplainResponse(BaseModel):
    relation: Relation
    provenance: List[Provenance]
    runs: List[ExtractionRun]


class RunStatusResponse(BaseModel):
    run: ExtractionRun


class ExplainEntityRelation(BaseModel):
    relation: Relation
    provenance: List[Provenance]
    runs: List[ExtractionRun]


class ExplainEntityResponse(BaseModel):
    entity: Entity
    relations: List[ExplainEntityRelation]
