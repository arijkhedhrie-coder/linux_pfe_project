from __future__ import annotations

import hashlib
import importlib
import math
import os
import re
import urllib.request
from typing import Any


def _normalize_ollama_base_url(raw_url: str | None) -> str:
    if not raw_url:
        return "http://localhost:11434"
    return raw_url.rstrip("/")


def ollama_embedding_url() -> str:
    base_url = _normalize_ollama_base_url(os.getenv("OLLAMA_BASE_URL"))
    if base_url.endswith("/api/embeddings"):
        return base_url
    return f"{base_url}/api/embeddings"


def ollama_server_available(timeout: float = 1.0) -> bool:
    base_url = _normalize_ollama_base_url(os.getenv("OLLAMA_BASE_URL"))
    if base_url.endswith("/api/embeddings"):
        health_url = base_url[: -len("/api/embeddings")] + "/api/tags"
    else:
        health_url = f"{base_url}/api/tags"

    try:
        with urllib.request.urlopen(health_url, timeout=timeout) as response:
            return 200 <= getattr(response, "status", 200) < 300
    except Exception:
        return False


def ollama_embedder_config() -> dict[str, Any]:
    return {
        "provider": "ollama",
        "config": {
            "model_name": "nomic-embed-text",
            "url": ollama_embedding_url(),
        },
    }


def huggingface_embedder_config() -> dict[str, Any]:
    return {
        "provider": "huggingface",
        "config": {"model": "sentence-transformers/all-MiniLM-L6-v2"},
    }


class LocalHashEmbedder:
    """Tiny offline embedder so CrewAI memory still works without Ollama."""

    def __init__(self, dimensions: int = 384) -> None:
        self.dimensions = dimensions

    def __call__(self, input: list[str]) -> list[list[float]]:
        return [self._embed_text(text) for text in input]

    def _embed_text(self, text: str) -> list[float]:
        vector = [0.0] * self.dimensions
        lowered = text.lower()
        tokens = re.findall(r"\w+", lowered)
        bigrams = [f"{tokens[i]}::{tokens[i + 1]}" for i in range(len(tokens) - 1)]
        features = tokens + bigrams

        if not features:
            return vector

        for feature in features:
            digest = hashlib.sha256(feature.encode("utf-8")).digest()
            for offset in range(0, 6, 2):
                bucket = int.from_bytes(digest[offset : offset + 2], "big") % self.dimensions
                sign = 1.0 if digest[offset + 16] % 2 == 0 else -1.0
                vector[bucket] += sign

        norm = math.sqrt(sum(value * value for value in vector))
        if norm == 0.0:
            return vector
        return [value / norm for value in vector]


def memory_embedder() -> Any:
    if ollama_server_available():
        return ollama_embedder_config()
    return LocalHashEmbedder()


def resolve_legacy_rag_storage() -> type[Any] | None:
    try:
        module = importlib.import_module("crewai.memory.storage.rag_storage")
    except ModuleNotFoundError:
        return None
    return getattr(module, "RAGStorage", None)


def patch_legacy_rag_storage_for_ollama() -> tuple[str, str]:
    rag_storage_cls = resolve_legacy_rag_storage()
    if rag_storage_cls is None:
        return (
            "skipped",
            "module legacy `crewai.memory.storage.rag_storage` absent dans cette version de CrewAI",
        )

    if getattr(rag_storage_cls, "_ollama_patch_applied", False):
        return ("applied", "patch deja applique")

    try:
        original_init = rag_storage_cls.__init__

        def _patched_init(self, *args, **kwargs):
            kwargs.setdefault("embedder_config", ollama_embedder_config())
            return original_init(self, *args, **kwargs)

        rag_storage_cls.__init__ = _patched_init
        rag_storage_cls._ollama_patch_applied = True
        return ("applied", "legacy RAGStorage patche pour Ollama")
    except Exception as exc:
        return ("error", f"{type(exc).__name__}: {exc}")
