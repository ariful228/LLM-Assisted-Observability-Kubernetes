#!/usr/bin/env python3
"""Seed the RAG databases locally (case-aiops pattern).

Re-ingests knowledge/**/*.md into:
  * pgvector   — hybrid dense (vector, local hashed or Ollama embeddings) + tsvector
  * OpenSearch — BM25 over the knowledge-chunks index
  * tfidf      — pure-python index (always reloaded in-process)

Usage:
  PYTHONPATH=. .venv/bin/python scripts/seed_rag.py
  PYTHONPATH=. .venv/bin/python scripts/seed_rag.py --embedder ollama:nomic-embed-text

Requires the local stack (Prometheus/OpenSearch + pgvector are optional; each
backend is seeded only when reachable):
  docker compose -f docker/docker-compose.yml up -d
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from backend.services.config import get_settings
from backend.services.rag import _load_chunks, rebuild_index  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--embedder",
        default="",
        help='embedder for pgvector vectors, e.g. "ollama:nomic-embed-text"; empty = local hashed',
    )
    parser.add_argument(
        "--store",
        default=None,
        help="rag_store to force: auto | pgvector | opensearch | tfidf (default = env RAG_STORE)",
    )
    args = parser.parse_args()

    settings = get_settings()
    if args.store:
        os.environ["RAG_STORE"] = args.store
        settings = get_settings()
    if args.embedder:
        os.environ["PGVECTOR_EMBEDDING_MODEL"] = args.embedder
        settings = get_settings()

    chunks = _load_chunks(settings.knowledge_dir)
    print(f"[seed-rag] knowledge source: {settings.knowledge_dir}")
    print(f"[seed-rag] chunks loaded: {len(chunks)} ({len({c['path'] for c in chunks})} docs)")

    index = rebuild_index()
    summary = index.reindex()
    for backend, result in summary.items():
        if backend == "tfidf":
            print(f"[seed-rag] TFIDF      in-process index reloaded ({result.get('chunks', '?')} chunks)")
        elif isinstance(result, dict) and result.get("reindexed"):
            print(
                f"[seed-rag] {backend.upper():<10} reindexed {result.get('chunks', '?')} chunks"
                f"  dim={result.get('dim', '-')}  model={result.get('model', '-')}"
            )
        else:
            print(f"[seed-rag] {backend.upper():<10} skipped ({result})")

    info = index.info()
    print("\n[seed-rag] RAG database information")
    print("-" * 60)
    for backend, meta in info["backends"].items():
        status = "OK" if meta.get("available") else "DOWN"
        details = (
            f"chunks={meta.get('chunks', '-')} model={meta.get('embedding_model', '-')}"
            f" last_indexed={meta.get('last_indexed') or '-'}"
        )
        print(f"  {backend:<10} {status:<4} {details}")
    print(f"active backends: {', '.join(info['active'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())