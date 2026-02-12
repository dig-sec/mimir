from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Tuple
from uuid import uuid4

from ..normalize import canonical_entity_key
from ..schemas import (
    Chunk,
    Entity,
    ExtractionRun,
    Provenance,
    Relation,
    Subgraph,
    SubgraphEdge,
    SubgraphNode,
)
from .base import GraphStore
from .run_store import RunStore


def _connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def _ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS entities (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            type TEXT,
            aliases TEXT,
            attrs TEXT,
            canonical_key TEXT UNIQUE
        );

        CREATE TABLE IF NOT EXISTS entity_keys (
            key TEXT PRIMARY KEY,
            entity_id TEXT NOT NULL,
            kind TEXT
        );

        CREATE TABLE IF NOT EXISTS relations (
            id TEXT PRIMARY KEY,
            subject_id TEXT NOT NULL,
            predicate TEXT NOT NULL,
            object_id TEXT NOT NULL,
            confidence REAL NOT NULL,
            attrs TEXT,
            UNIQUE(subject_id, predicate, object_id)
        );

        CREATE TABLE IF NOT EXISTS provenance (
            id TEXT PRIMARY KEY,
            source_uri TEXT NOT NULL,
            chunk_id TEXT NOT NULL,
            start_offset INTEGER NOT NULL,
            end_offset INTEGER NOT NULL,
            snippet TEXT NOT NULL,
            extraction_run_id TEXT NOT NULL,
            model TEXT NOT NULL,
            prompt_version TEXT NOT NULL,
            timestamp TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS relation_provenance (
            relation_id TEXT NOT NULL,
            provenance_id TEXT NOT NULL,
            PRIMARY KEY (relation_id, provenance_id)
        );

        CREATE TABLE IF NOT EXISTS runs (
            run_id TEXT PRIMARY KEY,
            started_at TEXT NOT NULL,
            model TEXT NOT NULL,
            prompt_version TEXT NOT NULL,
            params TEXT,
            status TEXT NOT NULL,
            error TEXT
        );

        CREATE TABLE IF NOT EXISTS documents (
            run_id TEXT PRIMARY KEY,
            source_uri TEXT NOT NULL,
            text TEXT NOT NULL,
            metadata TEXT
        );

        CREATE TABLE IF NOT EXISTS chunks (
            chunk_id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL,
            source_uri TEXT NOT NULL,
            start_offset INTEGER NOT NULL,
            end_offset INTEGER NOT NULL,
            text TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_rel_subject ON relations(subject_id);
        CREATE INDEX IF NOT EXISTS idx_rel_object ON relations(object_id);
        CREATE INDEX IF NOT EXISTS idx_prov_run ON provenance(extraction_run_id);
        """
    )
    conn.commit()


def _row_to_entity(row: sqlite3.Row) -> Entity:
    aliases = json.loads(row["aliases"]) if row["aliases"] else []
    attrs = json.loads(row["attrs"]) if row["attrs"] else {}
    return Entity(
        id=row["id"],
        name=row["name"],
        type=row["type"],
        aliases=aliases,
        attrs=attrs,
    )


def _row_to_relation(row: sqlite3.Row) -> Relation:
    attrs = json.loads(row["attrs"]) if row["attrs"] else {}
    return Relation(
        id=row["id"],
        subject_id=row["subject_id"],
        predicate=row["predicate"],
        object_id=row["object_id"],
        confidence=row["confidence"],
        attrs=attrs,
    )


def _row_to_provenance(row: sqlite3.Row) -> Provenance:
    return Provenance(
        provenance_id=row["id"],
        source_uri=row["source_uri"],
        chunk_id=row["chunk_id"],
        start_offset=row["start_offset"],
        end_offset=row["end_offset"],
        snippet=row["snippet"],
        extraction_run_id=row["extraction_run_id"],
        model=row["model"],
        prompt_version=row["prompt_version"],
        timestamp=datetime.fromisoformat(row["timestamp"]),
    )


def _row_to_run(row: sqlite3.Row) -> ExtractionRun:
    params = json.loads(row["params"]) if row["params"] else {}
    return ExtractionRun(
        run_id=row["run_id"],
        started_at=datetime.fromisoformat(row["started_at"]),
        model=row["model"],
        prompt_version=row["prompt_version"],
        params=params,
        status=row["status"],
        error=row["error"],
    )


def _merge_attrs(existing: Dict[str, Any], incoming: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(existing)
    for key, value in incoming.items():
        if (
            key in merged
            and isinstance(merged[key], (int, float))
            and isinstance(value, (int, float))
        ):
            merged[key] = merged[key] + value
        else:
            merged[key] = value
    return merged


class SQLiteGraphStore(GraphStore):
    def __init__(self, db_path: str) -> None:
        self.conn = _connect(db_path)
        _ensure_schema(self.conn)

    def upsert_entities(self, entities: List[Entity]) -> List[Entity]:
        stored: List[Entity] = []
        for entity in entities:
            key = canonical_entity_key(entity.name, entity.type)
            row = self.conn.execute(
                "SELECT * FROM entities WHERE canonical_key = ?", (key,)
            ).fetchone()
            if row:
                existing = _row_to_entity(row)
                merged_aliases = sorted({*existing.aliases, *entity.aliases})
                merged_attrs = {**existing.attrs, **entity.attrs}
                self.conn.execute(
                    """
                    UPDATE entities
                    SET name = ?, type = ?, aliases = ?, attrs = ?
                    WHERE id = ?
                    """,
                    (
                        entity.name,
                        entity.type,
                        json.dumps(merged_aliases),
                        json.dumps(merged_attrs),
                        existing.id,
                    ),
                )
                stored_entity = Entity(
                    id=existing.id,
                    name=entity.name,
                    type=entity.type,
                    aliases=merged_aliases,
                    attrs=merged_attrs,
                )
            else:
                entity_id = entity.id or str(uuid4())
                self.conn.execute(
                    """
                    INSERT INTO entities (id, name, type, aliases, attrs, canonical_key)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        entity_id,
                        entity.name,
                        entity.type,
                        json.dumps(entity.aliases),
                        json.dumps(entity.attrs),
                        key,
                    ),
                )
                stored_entity = Entity(
                    id=entity_id,
                    name=entity.name,
                    type=entity.type,
                    aliases=entity.aliases,
                    attrs=entity.attrs,
                )
            self._upsert_entity_keys(stored_entity)
            stored.append(stored_entity)
        self.conn.commit()
        return stored

    def _upsert_entity_keys(self, entity: Entity) -> None:
        keys = {canonical_entity_key(entity.name, entity.type)}
        for alias in entity.aliases:
            keys.add(canonical_entity_key(alias, entity.type))
        for key in keys:
            if not key:
                continue
            self.conn.execute(
                "INSERT OR IGNORE INTO entity_keys (key, entity_id, kind) VALUES (?, ?, ?)",
                (key, entity.id, "name"),
            )

    def upsert_relations(self, relations: List[Relation]) -> List[Relation]:
        stored: List[Relation] = []
        for relation in relations:
            row = self.conn.execute(
                """
                SELECT * FROM relations
                WHERE subject_id = ? AND predicate = ? AND object_id = ?
                """,
                (relation.subject_id, relation.predicate, relation.object_id),
            ).fetchone()
            if row:
                existing = _row_to_relation(row)
                confidence = max(existing.confidence, relation.confidence)
                merged_attrs = _merge_attrs(existing.attrs, relation.attrs)
                self.conn.execute(
                    """
                    UPDATE relations
                    SET confidence = ?, attrs = ?
                    WHERE id = ?
                    """,
                    (confidence, json.dumps(merged_attrs), existing.id),
                )
                stored.append(
                    Relation(
                        id=existing.id,
                        subject_id=existing.subject_id,
                        predicate=existing.predicate,
                        object_id=existing.object_id,
                        confidence=confidence,
                        attrs=merged_attrs,
                    )
                )
            else:
                relation_id = relation.id or str(uuid4())
                self.conn.execute(
                    """
                    INSERT INTO relations (id, subject_id, predicate, object_id, confidence, attrs)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        relation_id,
                        relation.subject_id,
                        relation.predicate,
                        relation.object_id,
                        relation.confidence,
                        json.dumps(relation.attrs),
                    ),
                )
                stored.append(
                    Relation(
                        id=relation_id,
                        subject_id=relation.subject_id,
                        predicate=relation.predicate,
                        object_id=relation.object_id,
                        confidence=relation.confidence,
                        attrs=relation.attrs,
                    )
                )
        self.conn.commit()
        return stored

    def attach_provenance(self, relation_id: str, provenance: Provenance) -> None:
        self.conn.execute(
            """
            INSERT OR IGNORE INTO provenance
            (id, source_uri, chunk_id, start_offset, end_offset, snippet, extraction_run_id, model, prompt_version, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                provenance.provenance_id,
                provenance.source_uri,
                provenance.chunk_id,
                provenance.start_offset,
                provenance.end_offset,
                provenance.snippet,
                provenance.extraction_run_id,
                provenance.model,
                provenance.prompt_version,
                provenance.timestamp.isoformat(),
            ),
        )
        self.conn.execute(
            "INSERT OR IGNORE INTO relation_provenance (relation_id, provenance_id) VALUES (?, ?)",
            (relation_id, provenance.provenance_id),
        )
        self.conn.commit()

    def get_entity(self, entity_id: str) -> Optional[Entity]:
        row = self.conn.execute(
            "SELECT * FROM entities WHERE id = ?", (entity_id,)
        ).fetchone()
        if not row:
            return None
        return _row_to_entity(row)

    def search_entities(
        self,
        query: str,
        entity_type: Optional[str] = None,
        canonical_key: Optional[str] = None,
    ) -> List[Entity]:
        if canonical_key:
            row = self.conn.execute(
                """
                SELECT e.* FROM entity_keys k
                JOIN entities e ON e.id = k.entity_id
                WHERE k.key = ?
                """,
                (canonical_key,),
            ).fetchall()
            if row:
                return [_row_to_entity(r) for r in row]
        params: List[Any] = [f"%{query.lower()}%"]
        sql = "SELECT * FROM entities WHERE lower(name) LIKE ?"
        if entity_type:
            sql += " AND type = ?"
            params.append(entity_type)
        rows = self.conn.execute(sql, params).fetchall()
        return [_row_to_entity(r) for r in rows]

    def get_subgraph(
        self,
        seed_entity_id: str,
        depth: int = 1,
        min_confidence: float = 0.0,
        source_uri: Optional[str] = None,
    ) -> Subgraph:
        visited = {seed_entity_id}
        frontier = {seed_entity_id}
        edges: Dict[str, Relation] = {}

        for _ in range(max(depth, 0)):
            if not frontier:
                break
            new_frontier: set[str] = set()
            relations = self._fetch_relations(frontier, min_confidence, source_uri)
            for relation in relations:
                edges[relation.id] = relation
                if relation.subject_id not in visited:
                    new_frontier.add(relation.subject_id)
                if relation.object_id not in visited:
                    new_frontier.add(relation.object_id)
            visited.update(new_frontier)
            frontier = new_frontier

        if not visited:
            return Subgraph(nodes=[], edges=[])

        nodes = self._fetch_entities_by_ids(visited)
        return Subgraph(
            nodes=[SubgraphNode(id=n.id, name=n.name, type=n.type) for n in nodes],
            edges=[
                SubgraphEdge(
                    id=e.id,
                    subject_id=e.subject_id,
                    predicate=e.predicate,
                    object_id=e.object_id,
                    confidence=e.confidence,
                    attrs=e.attrs,
                )
                for e in edges.values()
            ],
        )

    def get_full_graph(self, min_confidence: float = 0.0) -> Subgraph:
        """Return a Subgraph containing ALL entities and relations."""
        ent_rows = self.conn.execute("SELECT * FROM entities").fetchall()
        rel_rows = self.conn.execute(
            "SELECT * FROM relations WHERE confidence >= ?", (min_confidence,)
        ).fetchall()
        return Subgraph(
            nodes=[
                SubgraphNode(id=r["id"], name=r["name"], type=r["type"])
                for r in ent_rows
            ],
            edges=[
                SubgraphEdge(
                    id=r["id"],
                    subject_id=r["subject_id"],
                    predicate=r["predicate"],
                    object_id=r["object_id"],
                    confidence=r["confidence"],
                    attrs=json.loads(r["attrs"]) if r["attrs"] else {},
                )
                for r in rel_rows
            ],
        )

    def _fetch_entities_by_ids(self, ids: Iterable[str]) -> List[Entity]:
        placeholders = ",".join("?" for _ in ids)
        rows = self.conn.execute(
            f"SELECT * FROM entities WHERE id IN ({placeholders})", tuple(ids)
        ).fetchall()
        return [_row_to_entity(r) for r in rows]

    def _fetch_relations(
        self,
        entity_ids: Iterable[str],
        min_confidence: float,
        source_uri: Optional[str],
    ) -> List[Relation]:
        ids = list(entity_ids)
        if not ids:
            return []
        placeholders = ",".join("?" for _ in ids)
        base_params: List[Any] = ids + ids + [min_confidence]
        if source_uri:
            sql = f"""
                SELECT DISTINCT r.* FROM relations r
                JOIN relation_provenance rp ON rp.relation_id = r.id
                JOIN provenance p ON p.id = rp.provenance_id
                WHERE (r.subject_id IN ({placeholders}) OR r.object_id IN ({placeholders}))
                  AND r.confidence >= ?
                  AND p.source_uri = ?
            """
            params = base_params + [source_uri]
        else:
            sql = f"""
                SELECT r.* FROM relations r
                WHERE (r.subject_id IN ({placeholders}) OR r.object_id IN ({placeholders}))
                  AND r.confidence >= ?
            """
            params = base_params
        rows = self.conn.execute(sql, params).fetchall()
        return [_row_to_relation(r) for r in rows]

    def explain_edge(
        self, relation_id: str
    ) -> Tuple[Relation, List[Provenance], List[ExtractionRun]]:
        relation_row = self.conn.execute(
            "SELECT * FROM relations WHERE id = ?", (relation_id,)
        ).fetchone()
        if not relation_row:
            raise KeyError(f"Relation not found: {relation_id}")
        relation = _row_to_relation(relation_row)
        prov_rows = self.conn.execute(
            """
            SELECT p.* FROM provenance p
            JOIN relation_provenance rp ON rp.provenance_id = p.id
            WHERE rp.relation_id = ?
            ORDER BY p.timestamp DESC
            """,
            (relation_id,),
        ).fetchall()
        provenance = [_row_to_provenance(r) for r in prov_rows]
        run_ids = {p.extraction_run_id for p in provenance}
        runs: List[ExtractionRun] = []
        for run_id in run_ids:
            row = self.conn.execute(
                "SELECT * FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone()
            if row:
                runs.append(_row_to_run(row))
        return relation, provenance, runs

    def count_entities(self) -> int:
        row = self.conn.execute("SELECT count(*) FROM entities").fetchone()
        return int(row[0] if row else 0)

    def count_relations(self) -> int:
        row = self.conn.execute("SELECT count(*) FROM relations").fetchone()
        return int(row[0] if row else 0)


class SQLiteRunStore(RunStore):
    def __init__(self, db_path: str) -> None:
        self.conn = _connect(db_path)
        _ensure_schema(self.conn)

    def create_run(
        self,
        run: ExtractionRun,
        source_uri: str,
        text: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.conn.execute(
            """
            INSERT INTO runs (run_id, started_at, model, prompt_version, params, status, error)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run.run_id,
                run.started_at.isoformat(),
                run.model,
                run.prompt_version,
                json.dumps(run.params),
                run.status,
                run.error,
            ),
        )
        self.conn.execute(
            """
            INSERT INTO documents (run_id, source_uri, text, metadata)
            VALUES (?, ?, ?, ?)
            """,
            (
                run.run_id,
                source_uri,
                text,
                json.dumps(metadata or {}),
            ),
        )
        self.conn.commit()

    def update_run_status(
        self, run_id: str, status: str, error: Optional[str] = None
    ) -> None:
        self.conn.execute(
            "UPDATE runs SET status = ?, error = ? WHERE run_id = ?",
            (status, error, run_id),
        )
        self.conn.commit()

    def get_run(self, run_id: str) -> Optional[ExtractionRun]:
        row = self.conn.execute(
            "SELECT * FROM runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        if not row:
            return None
        return _row_to_run(row)

    def recover_stale_runs(self) -> int:
        """Reset any 'running' runs back to 'pending'."""
        cur = self.conn.execute(
            "UPDATE runs SET status = 'pending' WHERE status = 'running'"
        )
        self.conn.commit()
        return cur.rowcount

    def claim_next_run(self) -> Optional[ExtractionRun]:
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            # Prioritise smaller documents so more files get processed sooner
            row = self.conn.execute(
                "SELECT r.* FROM runs r "
                "LEFT JOIN documents d ON d.run_id = r.run_id "
                "WHERE r.status = 'pending' "
                "ORDER BY length(coalesce(d.text,'')), r.started_at LIMIT 1"
            ).fetchone()
            if not row:
                self.conn.execute("COMMIT")
                return None
            run_id = row["run_id"]
            updated = self.conn.execute(
                "UPDATE runs SET status = 'running' WHERE run_id = ? AND status = 'pending'",
                (run_id,),
            )
            self.conn.execute("COMMIT")
            if updated.rowcount != 1:
                return None
            return _row_to_run(row)
        except sqlite3.Error:
            self.conn.execute("ROLLBACK")
            raise

    def get_document(self, run_id: str) -> Optional[Dict[str, Any]]:
        row = self.conn.execute(
            "SELECT source_uri, text, metadata FROM documents WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        if not row:
            return None
        return {
            "source_uri": row["source_uri"],
            "text": row["text"],
            "metadata": json.loads(row["metadata"]) if row["metadata"] else {},
        }

    def store_chunks(self, run_id: str, chunks: List[Chunk]) -> None:
        for chunk in chunks:
            self.conn.execute(
                """
                INSERT OR IGNORE INTO chunks
                (chunk_id, run_id, source_uri, start_offset, end_offset, text)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    chunk.chunk_id,
                    run_id,
                    chunk.source_uri,
                    chunk.start_offset,
                    chunk.end_offset,
                    chunk.text,
                ),
            )
        self.conn.commit()

    def get_chunks(self, run_id: str) -> List[Chunk]:
        rows = self.conn.execute(
            "SELECT * FROM chunks WHERE run_id = ? ORDER BY start_offset",
            (run_id,),
        ).fetchall()
        return [
            Chunk(
                chunk_id=row["chunk_id"],
                source_uri=row["source_uri"],
                start_offset=row["start_offset"],
                end_offset=row["end_offset"],
                text=row["text"],
            )
            for row in rows
        ]

    def list_recent_runs(self, limit: int = 50) -> List[ExtractionRun]:
        rows = self.conn.execute(
            "SELECT * FROM runs ORDER BY started_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [_row_to_run(row) for row in rows]

    def delete_all_runs(self) -> int:
        row = self.conn.execute("SELECT count(*) FROM runs").fetchone()
        count = int(row[0] if row else 0)
        self.conn.execute("DELETE FROM chunks")
        self.conn.execute("DELETE FROM documents")
        self.conn.execute("DELETE FROM runs")
        self.conn.commit()
        return count

    def count_runs(
        self,
        status: Optional[str] = None,
        since: Optional[datetime] = None,
    ) -> int:
        where: List[str] = []
        params: List[Any] = []
        if status:
            where.append("status = ?")
            params.append(status)
        if since:
            where.append("started_at > ?")
            params.append(since.isoformat())

        sql = "SELECT count(*) FROM runs"
        if where:
            sql += " WHERE " + " AND ".join(where)
        row = self.conn.execute(sql, params).fetchone()
        return int(row[0] if row else 0)
