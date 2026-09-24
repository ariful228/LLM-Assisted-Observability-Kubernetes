"""RAG knowledge retrieval — three backends, fused, everything runnable locally.

  * TF-IDF (always on)      pure-python lexical index over knowledge/**/*.md
  * pgvector (optional)     local postgres+pgvector hybrid: dense (vector) +
                            tsvector (keyword). Embeddings via Ollama (local) or
                            a built-in deterministic hashed embedder.
  * OpenSearch (optional)   local OpenSearch BM25 over the knowledge-chunks index.

Selection is controlled by ``Settings.rag_store`` (auto | pgvector | opensearch |
tfidf). ``get_index()`` returns a facade that fuses scores from every reachable
backend, falling back gracefully so the demo still works with zero infra.
"""

from __future__ import annotations

import glob
import math
import os
import re
import threading
import time
from collections import Counter
from typing import Any, Optional

from backend.models.incident import KnowledgeDoc, RagSource
from backend.services.config import get_settings

_WORD = re.compile(r"[a-z0-9_]+")

# ---------------------------------------------------------------------------
# chunking + scoring helpers (shared by every backend)
# ---------------------------------------------------------------------------


def _tokenize(text: str) -> Counter[str]:
    return Counter(_WORD.findall(text.lower()))


def _scaled(counter: Counter[str], factor: float) -> Counter[str]:
    return Counter({k: v * factor for k, v in counter.items()})


def _safe_idf(doc_count: int, total: int) -> float:
    if doc_count == 0:
        return 0.0
    return math.log((1 + total) / (1 + doc_count)) + 1.0


def _chunk_markdown(raw: str) -> list[dict[str, str]]:
    lines = raw.splitlines()
    chunks: list[dict[str, str]] = []
    current = {"heading": "README", "text": []}
    for line in lines:
        if line.startswith("#"):
            if current["text"]:
                chunks.append({"heading": current["heading"], "text": "\n".join(current["text"]).strip()})
            current = {"heading": line.lstrip("#").strip(), "text": []}
        else:
            current["text"].append(line)
    if current["text"]:
        chunks.append({"heading": current["heading"], "text": "\n".join(current["text"]).strip()})
    final: list[dict[str, str]] = []
    for c in chunks:
        para = c["text"]
        if len(para) > 1500:
            step = 900
            for i in range(0, len(para), step):
                final.append({"heading": c["heading"], "text": para[i : i + step]})
        elif para:
            final.append(c)
    return [c for c in final if c["text"]]


def _derive_title(raw: str, default: str) -> str:
    for line in raw.splitlines():
        if line.startswith("# "):
            return line[2:].strip()
    return default.replace(".md", "").replace("-", " ").replace("_", " ")


def _load_chunks(knowledge_dir: str) -> list[dict[str, Any]]:
    """Collect all knowledge markdown into normalized chunk dicts."""
    if not os.path.isdir(knowledge_dir):
        return []
    files = sorted(glob.glob(os.path.join(knowledge_dir, "**", "*.md"), recursive=True))
    chunks: list[dict[str, Any]] = []
    for path in files:
        try:
            with open(path, encoding="utf-8") as fh:
                raw = fh.read()
        except OSError:
            continue
        relative = os.path.relpath(path, knowledge_dir)
        category = relative.split(os.sep)[0] if os.sep in relative else "general"
        title = _derive_title(raw, os.path.basename(path))
        for i, chunk in enumerate(_chunk_markdown(raw)):
            chunks.append(
                {
                    "id": f"{relative}#{i}",
                    "path": relative,
                    "category": category,
                    "title": title,
                    "heading": chunk["heading"],
                    "text": chunk["text"],
                }
            )
    return chunks


def _excerpt(text: str, query: str, limit: int) -> str:
    terms = [t for t in _WORD.findall(query.lower()) if t in text.lower()]
    idx = 0
    if terms:
        pos = text.lower().find(terms[0])
        if pos > 0:
            idx = max(0, pos - 40)
    return text[idx : idx + limit].strip()


def _to_source(chunk: dict[str, Any], query: str, score: float, backend: str = "tfidf") -> RagSource:
    return RagSource(
        document=chunk["path"],
        chunk=chunk["heading"] or chunk["id"],
        excerpt=_excerpt(chunk["text"], query, 260),
        score=round(float(score), 4),
        backend=backend,
    )


# ---------------------------------------------------------------------------
# TF-IDF backend (baseline, zero-dependency)
# ---------------------------------------------------------------------------


class TfidfIndex:
    def __init__(self, knowledge_dir: str) -> None:
        self.knowledge_dir = knowledge_dir
        self.chunks: list[dict[str, Any]] = []
        self.doc_titles: dict[str, str] = {}
        self._doc_freq: Counter[str] = Counter()
        self._rebuild()

    def _rebuild(self) -> None:
        self.chunks = []
        self._doc_freq = Counter()
        for chunk in _load_chunks(self.knowledge_dir):
            self.chunks.append(chunk)
            self._doc_freq.update(_tokenize(chunk["text"]).keys())

    def search(self, query: str, top_k: int = 4, filters: list[str] | None = None) -> list[dict[str, Any]]:
        if not self.chunks:
            return []
        q_tokens = _tokenize(query)
        if not q_tokens:
            return []
        n_docs = len(self.chunks)
        filtered = [
            c for c in self.chunks
            if not filters or c["category"] in filters or any(f in c["path"] for f in filters)
        ] or self.chunks
        results: list[tuple[float, dict[str, Any]]] = []
        for chunk in filtered:
            score = 0.0
            c_tokens = (
                _tokenize(chunk["text"])
                + _scaled(_tokenize(chunk["title"]), 0.5)
                + _scaled(_tokenize(chunk["heading"]), 0.3)
            )
            for term, qf in q_tokens.items():
                if term in c_tokens:
                    idf = _safe_idf(self._doc_freq.get(term, 0), n_docs)
                    score += qf * c_tokens[term] * idf
            if score > 0:
                results.append((score, chunk))
        results.sort(key=lambda r: r[0], reverse=True)
        return [{**c, "score": s} for s, c in results[:top_k]]

    def stats(self) -> dict[str, Any]:
        paths = {c["path"] for c in self.chunks}
        return {
            "backend": "tfidf",
            "available": True,
            "docs": len(paths),
            "chunks": len(self.chunks),
            "categories": sorted({c["category"] for c in self.chunks}),
            "last_indexed": None,
            "embedding_model": "tf-idf",
        }


# ---------------------------------------------------------------------------
# embedders (local deterministic hashed, or Ollama via HTTP)
# ---------------------------------------------------------------------------


def _fnv1a(text: str) -> int:
    h = 2166136261
    for ch in text.encode("utf-8"):
        h ^= ch
        h = (h * 16777619) & 0xFFFFFFFF
    return h


def _vector_plain(vec: list[float]) -> str:
    """pgvector accepts '[v,v,...]' as a string literal when cast ::vector."""
    return "[" + ",".join(_fmt_float(v) for v in vec) + "]"


def _fmt_float(v: float) -> str:
    return f"{v:.6f}"


class LocalEmbedder:
    """Deterministic hashed bag-of-words embedding — works fully offline."""

    def __init__(self, dim: int = 384) -> None:
        self.dim = dim

    @property
    def model(self) -> str:
        return "local:hashbow384"

    @property
    def spec(self) -> str:
        return self.model

    def embed(self, text: str) -> Optional[list[float]]:
        vec = [0.0] * self.dim
        for token, tf in _tokenize(text).items():
            if len(token) > 24:
                continue
            h = _fnv1a(token)
            idx = h % self.dim
            sign = 1.0 if (h & 0x8000) else -1.0
            vec[idx] += sign * (1.0 + math.log1p(tf))
        norm = math.sqrt(sum(v * v for v in vec)) or 1.0
        return [v / norm for v in vec]


class OllamaEmbedder:
    """Local Ollama embeddings (e.g. nomic-embed-text) via the HTTP API."""

    def __init__(self, url: str, model: str) -> None:
        self.url = url.rstrip("/")
        self.model = model
        self._dim: int | None = None

    @property
    def spec(self) -> str:
        return f"ollama:{self.model}"

    def embed(self, text: str) -> Optional[list[float]]:
        try:
            import httpx

            r = httpx.post(
                f"{self.url}/api/embeddings",
                json={"model": self.model, "prompt": text[:8000]},
                timeout=30.0,
            )
            r.raise_for_status()
            vec = r.json()["embedding"]
            self._dim = len(vec)
            return [float(v) for v in vec]
        except Exception:
            return None


def _build_embedder(model_spec: str) -> Any:
    if not model_spec:
        return LocalEmbedder()
    if model_spec.startswith("ollama:"):
        name = model_spec.split(":", 1)[1]
        return OllamaEmbedder(os.environ.get("OLLAMA_HOST", "http://localhost:11434"), name)
    return LocalEmbedder()


# ---------------------------------------------------------------------------
# pgvector backend (hybrid dense + tsvector)
# ---------------------------------------------------------------------------


class PgvectorBackend:
    def __init__(self, url: str, embedder: Any) -> None:
        self.url = url
        self.embedder = embedder
        self._conn = None
        self._dim = 0

    def available(self) -> bool:
        try:
            import psycopg  # noqa: PLC0415

            conn = self._connect(psycopg)
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
                cur.fetchone()
            return True
        except Exception:
            return False

    def _connect(self, psycopg: Any):
        import urllib.parse  # noqa: PLC0415

        url = self.url.replace("postgresql://", "postgresql://", 1).replace(
            "postgres://", "postgresql://", 1
        )
        # autocommit: reads must never hold an open transaction (and therefore an
        # ACCESS SHARE lock) on knowledge_chunks, or DROP/VACUUM during a reindex
        # blocks forever and every later query queues up behind it.
        return psycopg.connect(url, connect_timeout=3, autocommit=True)

    def _ensure_conn(self):
        if self._conn is None:
            import psycopg  # noqa: PLC0415

            self._conn = self._connect(psycopg)
        return self._conn

    def ensure_schema(self, dim: int) -> None:
        self._dim = dim
        conn = self._ensure_conn()
        with conn.cursor() as cur:
            cur.execute("CREATE EXTENSION IF NOT EXISTS vector")
            cur.execute("DROP TABLE IF EXISTS knowledge_chunks")
            # pgvector dimensions cannot be a bind parameter — inline the literal.
            cur.execute(
                f"""
                CREATE TABLE knowledge_chunks (
                    id       text primary key,
                    path     text not null,
                    category text,
                    heading  text,
                    title    text,
                    text     text not null,
                    embedding vector({int(dim)}),
                    ts       tsvector
                )
                """
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS knowledge_chunks_hnsw "
                "ON knowledge_chunks USING hnsw (embedding vector_cosine_ops)"
            )
            cur.execute("CREATE INDEX IF NOT EXISTS knowledge_chunks_gin ON knowledge_chunks USING gin (ts)")
            cur.execute("CREATE TABLE IF NOT EXISTS rag_meta (k text primary key, v text)")
        conn.commit()

    def reindex(self, chunks: list[dict[str, Any]]) -> dict[str, Any]:
        dim = 0
        if chunks:
            vec = self.embedder.embed(chunks[0]["text"])
            dim = len(vec) if vec else (self._dim or 0)
        if dim == 0:
            return {"reindexed": False, "reason": "no embedder signal"}

        self.ensure_schema(dim)
        conn = self._ensure_conn()
        now = time.strftime("%Y-%m-%dT%H:%M:%S")
        rows = []
        for c in chunks:
            emb = self.embedder.embed(c["text"])
            rows.append(
                (
                    c["id"], c["path"], c["category"], c["heading"], c["title"],
                    c["text"],
                    _vector_plain(emb) if emb else None,
                    f"{c['title']} {c['heading']} {c['text']}",
                )
            )
        with conn.cursor() as cur:
            cur.executemany(
                """
                INSERT INTO knowledge_chunks
                    (id, path, category, heading, title, text, embedding, ts)
                VALUES (%s, %s, %s, %s, %s, %s, %s::vector, to_tsvector('simple', %s))
                """,
                rows,
            )
            cur.execute(
                "INSERT INTO rag_meta (k, v) VALUES (%s, %s) "
                "ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v",
                ("last_indexed", now),
            )
        conn.commit()
        return {"reindexed": True, "chunks": len(rows), "dim": dim, "model": self.embedder.spec}

    # Pyformat list syntax for the keyword query — we build tsquery ourselves.
    @staticmethod
    def _ts_query(query: str) -> str:
        tokens = [t for t in _WORD.findall(query.lower()) if len(t) > 1]
        return " & ".join(f"'{t}'" for t in tokens[:8]) or "'x'"

    def search(self, query: str, top_k: int = 4, filters: list[str] | None = None) -> list[dict[str, Any]]:
        try:
            return self._search(query, top_k, filters)
        except Exception:
            return []

    def _search(self, query: str, top_k: int, filters: list[str] | None) -> list[dict[str, Any]]:
        conn = self._ensure_conn()
        results: dict[str, tuple[float, dict[str, Any]]] = {}
        where = self._filters_sql(filters)

        with conn.cursor() as cur:
            tsq = self._ts_query(query)
            cur.execute(
                f"""
                SELECT id, path, category, heading, title, text,
                       ts_rank_cd(ts, plainto_tsquery('simple', %s)) AS s
                FROM knowledge_chunks
                WHERE ts @@ plainto_tsquery('simple', %s) {where}
                ORDER BY s DESC LIMIT %s
                """,
                (query, query, top_k),
            )
            for row in cur.fetchall():
                cid, path, cat, head, title, text, s = row
                if cid not in results or s > results[cid][0]:
                    results[cid] = (float(s), self._chunk(cid, path, cat, head, title, text))

            qv = self.embedder.embed(query)
            if qv and len(qv) == self._dim:
                cur.execute(
                    f"""
                    SELECT id, path, category, heading, title, text,
                           (1 - (embedding <=> %s::vector)) AS s
                    FROM knowledge_chunks
                    WHERE embedding IS NOT NULL {where}
                    ORDER BY s DESC LIMIT %s
                    """,
                    (_vector_plain(qv), top_k),
                )
                for row in cur.fetchall():
                    cid, path, cat, head, title, text, s = row
                    s = float(s)
                    if cid not in results or s > results[cid][0]:
                        results[cid] = (s, self._chunk(cid, path, cat, head, title, text))
        out = sorted(results.items(), key=lambda kv: kv[1][0], reverse=True)[:top_k]
        return [{**c, "score": s} for _cid, (s, c) in out]

    @staticmethod
    def _chunk(cid, path, cat, head, title, text) -> dict[str, Any]:
        return {"id": cid, "path": path, "category": cat, "heading": head, "title": title, "text": text}

    def _filters_sql(self, filters: list[str] | None) -> str:
        if not filters:
            return ""
        return ""  # filters applied in python for the DB-backed stores (rare path)

    def stats(self) -> dict[str, Any]:
        try:
            conn = self._ensure_conn()
            with conn.cursor() as cur:
                cur.execute("SELECT count(*), count(embedding) FROM knowledge_chunks")
                n, n_emb = cur.fetchone()
                cur.execute("SELECT v FROM rag_meta WHERE k = 'last_indexed'")
                row = cur.fetchone()
            return {
                "backend": "pgvector",
                "available": True,
                "docs": 0,
                "chunks": int(n or 0),
                "vectors": int(n_emb or 0),
                "last_indexed": row[0] if row else None,
                "embedding_model": self.embedder.spec,
                "dim": self._dim,
            }
        except Exception as exc:
            return {"backend": "pgvector", "available": False, "error": str(exc)}


# ---------------------------------------------------------------------------
# OpenSearch backend (BM25 over knowledge-chunks)
# ---------------------------------------------------------------------------


class OpensearchBackend:
    def __init__(self, url: str, index: str) -> None:
        self.url = url.rstrip("/")
        self.index = index
        self.meta_index = "knowledge-meta"

    def _http(self) -> Any:
        import httpx  # noqa: PLC0415

        return httpx.Client(base_url=self.url, timeout=5.0)

    def available(self) -> bool:
        try:
            with self._http() as c:
                r = c.get("/_cluster/health", params={"timeout": "2s"})
                return r.status_code == 200 and r.json().get("status") in ("green", "yellow")
        except Exception:
            return False

    def ensure_index(self) -> None:
        mapping = {
            "settings": {"number_of_shards": 1, "number_of_replicas": 0},
            "mappings": {
                "properties": {
                    "id": {"type": "keyword"},
                    "path": {"type": "keyword"},
                    "category": {"type": "keyword"},
                    "heading": {"type": "text"},
                    "title": {"type": "text"},
                    "text": {"type": "text", "analyzer": "english"},
                }
            },
        }
        with self._http() as c:
            if c.head(f"/{self.index}").status_code == 200:
                return
            c.put(f"/{self.index}", json=mapping)

    def reindex(self, chunks: list[dict[str, Any]]) -> dict[str, Any]:
        now = time.strftime("%Y-%m-%dT%H:%M:%S")
        with self._http() as c:
            c.delete(f"/{self.index}").raise_for_status() if c.head(f"/{self.index}").status_code == 200 else None
            self.ensure_index()
            body: list[str] = []
            for ch in chunks:
                body.append('{"index": {"_index": %s, "_id": %s}}' % (
                    _json_str(self.index), _json_str(ch["id"])))
                body.append(_json_obj({k: ch[k] for k in ("id", "path", "category", "heading", "title", "text")}))
            if body:
                resp = c.post(
                    "/_bulk",
                    content=("\n".join(body) + "\n").encode(),
                    headers={"Content-Type": "application/x-ndjson"},
                )
                resp.raise_for_status()
                rj = resp.json()
                if rj.get("errors"):
                    return {"reindexed": False, "reason": "bulk errors"}
            c.put(f"/{self.meta_index}/_doc/meta", json={"last_indexed": now}).raise_for_status()
            c.post("/_refresh").raise_for_status()
        return {"reindexed": True, "chunks": len(chunks), "index": self.index, "model": "bm25"}

    def search(self, query: str, top_k: int = 4, filters: list[str] | None = None) -> list[dict[str, Any]]:
        must: list[Any] = [
            {"multi_match": {"query": query, "fields": ["text^2", "title^1.5", "heading^1.2"]}}
        ]
        if filters:
            f = [x for x in filters]
            terms = [x for x in f if not path_pattern(x)]
            path_like = [x for x in f if path_pattern(x)]
            parts = []
            if terms:
                parts.append({"terms": {"category": terms}})
            if path_like:
                for p in path_like:
                    suffix = p[1:] if p.startswith("/") else p
                    parts.append({"wildcard": {"path": f"*{suffix}*"}})
            if parts:
                must.append({"bool": {"filter": parts}})
        body = {"query": {"bool": {"must": must}}, "size": top_k}
        try:
            with self._http() as c:
                r = c.post(f"/{self.index}/_search", json=body)
                if r.status_code == 404:
                    return []
                r.raise_for_status()
                hits = r.json()["hits"]["hits"]
            return [{**h["_source"], "score": float(h["_score"])} for h in hits]
        except Exception:
            return []

    def stats(self) -> dict[str, Any]:
        try:
            with self._http() as c:
                r = c.get(f"/{self.index}/_count")
                count = r.json().get("count", 0) if r.status_code == 200 else 0
                meta = None
                mr = c.get(f"/{self.meta_index}/_doc/meta")
                if mr.status_code == 200:
                    meta = mr.json().get("_source", {}).get("last_indexed")
            return {
                "backend": "opensearch",
                "available": True,
                "docs": 0,
                "chunks": int(count),
                "last_indexed": meta,
                "embedding_model": "bm25-english",
                "index": self.index,
            }
        except Exception as exc:
            return {"backend": "opensearch", "available": False, "error": str(exc)}


def path_pattern(x: str) -> bool:
    return "/" in x


def _json_str(s: str) -> str:
    s = s.replace("\\", "\\\\").replace('"', '\\"')
    s = s.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    return '"' + s + '"'


def _json_obj(d: dict[str, Any]) -> str:
    return "{ " + ", ".join(f'{_json_str(k)}: {_json_str(str(v))}' for k, v in d.items()) + " }"


# ---------------------------------------------------------------------------
# fused facade
# ---------------------------------------------------------------------------


class KnowledgeIndex:
    """Facade: fuses TF-IDF + pgvector + OpenSearch hits into top-k RagSources."""

    _WEIGHT = {"tfidf": 1.0, "pgvector": 1.2, "opensearch": 1.1}

    def __init__(self, settings: Any | None = None) -> None:
        self.settings = settings or get_settings()
        self.tfidf = TfidfIndex(self.settings.knowledge_dir)
        self._pg: PgvectorBackend | None = None
        self._os: OpensearchBackend | None = None
        self.chunks = self.tfidf.chunks
        self.doc_titles = self.tfidf.doc_titles

    # -- backends ---------------------------------------------------------
    @property
    def mode(self) -> str:
        return self.settings.rag_store

    def _pgbackend(self) -> PgvectorBackend | None:
        if self.mode == "opensearch":
            return None
        if self._pg is None:
            self._pg = PgvectorBackend(
                self.settings.pgvector_url_value(),
                _build_embedder(self.settings.pgvector_embedding_model),
            )
        return self._pg

    def _osbackend(self) -> OpensearchBackend | None:
        if self.mode == "pgvector":
            return None
        if self._os is None:
            self._os = OpensearchBackend(
                self.settings.opensearch_url, self.settings.opensearch_index_knowledge
            )
        return self._os

    def available_backends(self) -> list[str]:
        backends: list[str] = []
        if self.tfidf.chunks:
            backends.append("tfidf")
        if self.mode != "opensearch":
            pg = self._pgbackend()
            if pg and pg.available():
                backends.append("pgvector")
        if self.mode != "pgvector":
            os_ = self._osbackend()
            if os_ and os_.available():
                backends.append("opensearch")
        return backends

    # -- retrieval --------------------------------------------------------
    def search(self, query: str, top_k: int = 4, filters: list[str] | None = None) -> list[RagSource]:
        hits: dict[str, tuple[float, dict[str, Any], str]] = {}
        for backend_name, results in self._retrieve(query, top_k * 3, filters):
            best = max((r["score"] for r in results), default=0.0) or 1.0
            weight = self._WEIGHT[backend_name]
            for r in results:
                cid = r["id"]
                merged_score = weight * (r["score"] / best)
                if cid not in hits or merged_score > hits[cid][0]:
                    hits[cid] = (merged_score, r, backend_name)
        ranked = sorted(hits.items(), key=lambda kv: kv[1][0], reverse=True)[:top_k]
        return [
            _to_source(chunk, query, score, backend=backend)
            for _cid, (score, chunk, backend) in ranked
        ]

    def _retrieve(self, query: str, top_k: int, filters: list[str] | None):
        yield "tfidf", self.tfidf.search(query, top_k=top_k, filters=filters)
        if self.mode != "opensearch":
            pg = self._pgbackend()
            if pg and pg.available():
                yield "pgvector", pg.search(query, top_k=top_k, filters=filters)
        if self.mode != "pgvector":
            os_ = self._osbackend()
            if os_ and os_.available():
                yield "opensearch", os_.search(query, top_k=top_k, filters=filters)

    # -- index metadata ----------------------------------------------------
    def documents(self) -> list[KnowledgeDoc]:
        seen: set[str] = set()
        result = []
        for chunk in self.tfidf.chunks:
            key = chunk["path"]
            if key in seen:
                continue
            seen.add(key)
            result.append(
                KnowledgeDoc(
                    id=key,
                    path=key,
                    category=chunk["category"],
                    title=chunk["title"],
                    excerpt=chunk["text"][:200],
                )
            )
        return result

    def recent_documents(self, limit: int = 10) -> list[dict[str, str]]:
        return [
            {"path": d.path, "category": d.category, "title": d.title}
            for d in self.documents()[:limit]
        ]

    # -- management --------------------------------------------------------
    def reindex(self) -> dict[str, Any]:
        self.tfidf._rebuild()
        self.chunks = self.tfidf.chunks
        summary: dict[str, Any] = {"tfidf": self.tfidf.stats()}
        if self.mode != "opensearch":
            pg = self._pgbackend()
            if pg and pg.available():
                summary["pgvector"] = pg.reindex(self.tfidf.chunks)
        if self.mode != "pgvector":
            os_ = self._osbackend()
            if os_ and os_.available():
                summary["opensearch"] = os_.reindex(self.tfidf.chunks)
        return summary

    def info(self) -> dict[str, Any]:
        backends: dict[str, Any] = {}
        backends["tfidf"] = self.tfidf.stats()
        if self.mode != "opensearch":
            pg = self._pgbackend()
            if pg and pg.available():
                backends["pgvector"] = pg.stats()
            else:
                backends["pgvector"] = {
                    "backend": "pgvector",
                    "available": False,
                    "error": "unreachable — start docker compose -f docker/docker-compose.yml up pgvector",
                }
        if self.mode != "pgvector":
            os_ = self._osbackend()
            if os_ and os_.available():
                backends["opensearch"] = os_.stats()
            else:
                backends["opensearch"] = {
                    "backend": "opensearch",
                    "available": False,
                    "error": "unreachable — start docker compose -f docker/docker-compose.yml up opensearch",
                }
        active = self.available_backends()
        return {
            "store_mode": self.mode,
            "active": active,
            "backends": backends,
            "documents": len({c["path"] for c in self.tfidf.chunks}),
            "chunks": len(self.tfidf.chunks),
            "categories": sorted({c["category"] for c in self.tfidf.chunks}),
            "knowledge_dir": self.settings.knowledge_dir,
        }


_index: KnowledgeIndex | None = None
_index_lock = threading.Lock()


def get_index() -> KnowledgeIndex:
    global _index
    if _index is None:
        with _index_lock:
            if _index is None:
                _index = KnowledgeIndex()
    return _index


def rebuild_index() -> KnowledgeIndex:
    global _index
    with _index_lock:
        _index = KnowledgeIndex()
    return _index