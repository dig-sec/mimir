"""Ingest, upload, run management, and filesystem scan routes."""

from __future__ import annotations

import os
from datetime import datetime
from typing import List
from uuid import uuid4

from fastapi import APIRouter, File, HTTPException, Query, UploadFile

from ...connectors.aikg import ingest_aikg_triples, parse_aikg_file
from ...schemas import ExtractionRun, IngestRequest, IngestResponse, RunStatusResponse
from ...stix.importer import ingest_stix_bundle, parse_stix_file
from ..tasks import TaskStatus, task_manager
from ._helpers import extract_text, graph_store, is_stix_bundle, run_store, settings

router = APIRouter()


@router.post("/api/upload")
async def upload_documents(files: List[UploadFile] = File(...)):
    """Upload documents (text, PDF, STIX JSON, or AIKG triples JSON)."""
    results = []
    max_upload_bytes = settings.max_document_size_mb * 1024 * 1024
    for f in files:
        raw = await f.read(max_upload_bytes + 1)
        filename = f.filename or ""
        if len(raw) > max_upload_bytes:
            results.append(
                {
                    "filename": filename,
                    "status": "error",
                    "error": (
                        f"File exceeds {settings.max_document_size_mb}MB upload limit"
                    ),
                }
            )
            continue

        # ── STIX bundle fast-path ──
        if filename.lower().endswith(".json") and is_stix_bundle(raw):
            try:
                bundle = parse_stix_file(raw, filename)
                stix_result = ingest_stix_bundle(
                    bundle, graph_store, source_uri=f"stix://{filename}"
                )
                results.append(
                    {
                        "filename": filename,
                        "status": "completed",
                        "type": "stix",
                        "entities": stix_result.entities_created,
                        "relations": stix_result.relations_created,
                        "skipped": stix_result.objects_skipped,
                        "errors": stix_result.errors,
                    }
                )
            except ValueError as exc:
                results.append(
                    {
                        "filename": filename,
                        "status": "error",
                        "type": "stix",
                        "error": str(exc),
                    }
                )
            continue

        # ── AIKG triples fast-path ──
        if filename.lower().endswith(".json"):
            try:
                triples = parse_aikg_file(raw, filename)
                aikg_result = ingest_aikg_triples(
                    triples,
                    graph_store,
                    source_uri=f"upload://{filename}",
                    include_inferred=settings.aikg_import_include_inferred,
                    min_inferred_confidence=settings.aikg_import_min_inferred_confidence,
                    allow_via_predicates=settings.aikg_import_allow_via_predicates,
                )
                results.append(
                    {
                        "filename": filename,
                        "status": "completed",
                        "type": "aikg",
                        "triples_seen": aikg_result.triples_seen,
                        "triples_imported": aikg_result.triples_imported,
                        "entities": aikg_result.entities_created,
                        "relations": aikg_result.relations_created,
                        "skipped_invalid": aikg_result.skipped_invalid,
                        "skipped_inferred": aikg_result.skipped_inferred,
                        "skipped_low_confidence": aikg_result.skipped_low_confidence,
                        "errors": aikg_result.errors[:20],
                    }
                )
                continue
            except ValueError:
                pass

        # ── Regular document: enqueue for LLM extraction ──
        text = extract_text(raw, filename)
        source_uri = f"upload://{filename}"

        run_id = str(uuid4())
        run = ExtractionRun(
            run_id=run_id,
            started_at=datetime.utcnow(),
            model=settings.ollama_model,
            prompt_version=settings.prompt_version,
            params={
                "chunk_size": settings.chunk_size,
                "chunk_overlap": settings.chunk_overlap,
            },
            status="pending",
            error=None,
        )
        run_store.create_run(
            run, source_uri, text, {"filename": filename, "size": len(raw)}
        )
        results.append({"run_id": run_id, "filename": filename, "status": "pending"})
    return results


@router.get("/api/runs")
def list_runs():
    """List recent extraction runs."""
    runs = run_store.list_recent_runs(limit=50)
    return [
        {
            "run_id": r.run_id,
            "status": r.status,
            "model": r.model,
            "started_at": r.started_at.isoformat(),
        }
        for r in runs
    ]


@router.delete("/api/runs")
def delete_all_runs():
    """Delete all runs and associated documents/chunks."""
    count = run_store.delete_all_runs()
    return {"deleted": count}


@router.post("/ingest", response_model=IngestResponse)
def ingest(payload: IngestRequest) -> IngestResponse:
    if len(payload.text) > settings.max_total_chars_per_run:
        raise HTTPException(
            status_code=413,
            detail=(f"text exceeds {settings.max_total_chars_per_run} character limit"),
        )
    payload_bytes = len(payload.text.encode("utf-8"))
    if payload_bytes > settings.max_document_size_mb * 1024 * 1024:
        raise HTTPException(
            status_code=413,
            detail=f"text exceeds {settings.max_document_size_mb}MB size limit",
        )

    run_id = str(uuid4())
    run = ExtractionRun(
        run_id=run_id,
        started_at=datetime.utcnow(),
        model=settings.ollama_model,
        prompt_version=settings.prompt_version,
        params={
            "chunk_size": settings.chunk_size,
            "chunk_overlap": settings.chunk_overlap,
        },
        status="pending",
        error=None,
    )
    run_store.create_run(run, payload.source_uri, payload.text, payload.metadata)
    return IngestResponse(run_id=run_id, status=run.status)


@router.get("/runs/{run_id}", response_model=RunStatusResponse)
def run_status(run_id: str) -> RunStatusResponse:
    run = run_store.get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return RunStatusResponse(run=run)


@router.post("/api/scan")
async def scan_directory(
    extensions: str = Query(default=".txt,.md,.pdf,.json,.html,.csv,.xml,.yaml,.yml"),
):
    """Scan watched folders recursively and ingest all matching files."""
    import pathlib

    dirs = settings.watched_folders_list

    if not dirs:
        raise HTTPException(status_code=400, detail="No watched folders configured")

    valid_dirs = [d for d in dirs if pathlib.Path(d).is_dir()]
    if not valid_dirs:
        raise HTTPException(
            status_code=400,
            detail=f"No watched folders found: {settings.watched_folders}",
        )

    exts = set(e.strip().lower() for e in extensions.split(","))

    task = task_manager.create(
        "filesystem_scan",
        {"watched_folders": valid_dirs},
    )
    task_manager.update(
        task.id,
        status=TaskStatus.RUNNING,
        progress="Discovering files...",
    )

    async def _run():
        import asyncio

        await asyncio.to_thread(_scan_files_sync, task.id, valid_dirs, exts)

    def _scan_files_sync(task_id: str, scan_dirs: List[str], exts_set: set):
        import pathlib

        task_manager.update(task_id, progress="Discovering files...")
        files: List[str] = []
        for d in scan_dirs:
            root = pathlib.Path(d)
            for p in root.rglob("*"):
                if p.is_file() and p.suffix.lower() in exts_set:
                    files.append(str(p))
        files.sort()

        if not files:
            task_manager.update(
                task_id,
                status=TaskStatus.COMPLETED,
                progress="No matching files found",
                finished_at=datetime.utcnow().isoformat(),
            )
            return

        task_manager.update(
            task_id, progress=f"Found {len(files)} files, starting ingestion..."
        )

        processed = 0
        stix_ok = 0
        aikg_ok = 0
        queued = 0
        errors = []

        for filepath in files:
            processed += 1
            fname = os.path.basename(filepath)
            try:
                if (
                    os.path.getsize(filepath)
                    > settings.max_document_size_mb * 1024 * 1024
                ):
                    errors.append(
                        f"{fname}: exceeds {settings.max_document_size_mb}MB limit"
                    )
                    continue
                with open(filepath, "rb") as fh:
                    raw = fh.read()
                if len(raw) < 10:
                    continue
                if filepath.lower().endswith(".json") and is_stix_bundle(raw):
                    try:
                        bundle = parse_stix_file(raw, fname)
                        ingest_stix_bundle(
                            bundle, graph_store, source_uri=f"file://{filepath}"
                        )
                        stix_ok += 1
                    except Exception as exc:
                        errors.append(f"{fname}: STIX error: {exc}")
                    continue
                if filepath.lower().endswith(".json"):
                    try:
                        triples = parse_aikg_file(raw, fname)
                        ingest_aikg_triples(
                            triples,
                            graph_store,
                            source_uri=f"file://{filepath}",
                            include_inferred=settings.aikg_import_include_inferred,
                            min_inferred_confidence=settings.aikg_import_min_inferred_confidence,
                            allow_via_predicates=settings.aikg_import_allow_via_predicates,
                        )
                        aikg_ok += 1
                        continue
                    except ValueError:
                        pass
                text = extract_text(raw, fname)
                if len(text.strip()) < 50:
                    continue
                source_uri = f"file://{filepath}"
                run_id = str(uuid4())
                run = ExtractionRun(
                    run_id=run_id,
                    started_at=datetime.utcnow(),
                    model=settings.ollama_model,
                    prompt_version=settings.prompt_version,
                    params={
                        "chunk_size": settings.chunk_size,
                        "chunk_overlap": settings.chunk_overlap,
                    },
                    status="pending",
                    error=None,
                )
                run_store.create_run(
                    run,
                    source_uri,
                    text,
                    {"filename": fname, "path": filepath, "size": len(raw)},
                )
                queued += 1
            except Exception as exc:
                errors.append(f"{fname}: {exc}")

            if processed % 25 == 0 or processed == len(files):
                task_manager.update(
                    task_id,
                    progress=(
                        f"Scanned {processed}/{len(files)}: {queued} queued, "
                        f"{stix_ok} STIX, {aikg_ok} AIKG, {len(errors)} errors"
                    ),
                )

        task_manager.update(
            task_id,
            status=TaskStatus.COMPLETED,
            progress=(
                f"Done: {queued} queued for LLM, "
                f"{stix_ok} STIX imported, {aikg_ok} AIKG imported, "
                f"{len(errors)} errors"
            ),
            detail={
                "total_scanned": processed,
                "queued_for_llm": queued,
                "stix_imported": stix_ok,
                "aikg_imported": aikg_ok,
                "errors": errors[:50],
            },
            finished_at=datetime.utcnow().isoformat(),
        )

    task_manager.start_async(task.id, _run())
    return {"task_id": task.id, "status": "running"}
