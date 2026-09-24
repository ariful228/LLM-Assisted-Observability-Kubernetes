"""Knowledge / RAG API."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter

from backend.models.incident import RagQueryRequest
from backend.services.rag import get_index, rebuild_index

router = APIRouter(prefix="/api/knowledge", tags=["knowledge"])


@router.get("")
def list_knowledge() -> dict[str, Any]:
    index = get_index()
    return {
        "documents": [d.model_dump(mode="json") for d in index.documents()],
        "count": len(index.chunks),
        "categories": sorted({c["category"] for c in index.chunks}),
    }


@router.post("/search")
def search_knowledge(req: RagQueryRequest) -> dict[str, Any]:
    results = get_index().search(req.query, top_k=req.top_k, filters=req.filters or None)
    return {
        "query": req.query,
        "sources": [r.model_dump(mode="json") for r in results],
        "count": len(results),
        "backends": get_index().available_backends(),
    }


@router.get("/db/info")
def rag_db_info() -> dict[str, Any]:
    """RAG database information — backend availability, freshness, model."""
    return get_index().info()


@router.post("/db/reindex")
def rag_db_reindex() -> dict[str, Any]:
    """Re-ingest knowledge/**/*.md into every reachable RAG backend."""
    index = rebuild_index()
    summary = index.reindex()
    return {"reindexed": True, "summary": summary, "info": index.info()}