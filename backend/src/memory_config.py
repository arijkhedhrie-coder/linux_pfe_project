from __future__ import annotations

import os

from src.crewai_compat import (
    huggingface_embedder_config,
    memory_embedder,
    ollama_embedder_config,
    ollama_server_available,
    resolve_legacy_rag_storage,
)

try:
    from crewai.memory import Memory
except ImportError:
    Memory = None  # type: ignore[assignment]

try:
    from crewai.memory import EntityMemory, LongTermMemory, ShortTermMemory
    from crewai.memory.storage.ltm_sqlite_storage import LTMSQLiteStorage

    RAGStorage = resolve_legacy_rag_storage()
    LEGACY_MEMORY_API = RAGStorage is not None
except ImportError:
    LEGACY_MEMORY_API = False

if not LEGACY_MEMORY_API and Memory is None:
    raise ImportError("Aucune API mémoire compatible n'a été trouvée dans CrewAI.")


def _ollama_available() -> bool:
    try:
        import ollama  # noqa: F401

        return True
    except Exception:
        return False


USE_OLLAMA = _ollama_available()
USE_OLLAMA_SERVER = ollama_server_available()

if "CREWAI_STORAGE_DIR" not in os.environ:
    os.environ["CREWAI_STORAGE_DIR"] = os.path.join(os.getcwd(), ".crewai")


def _embedder_config() -> dict:
    return (
        ollama_embedder_config()
        if USE_OLLAMA and USE_OLLAMA_SERVER
        else huggingface_embedder_config()
    )


# ================================
# SHORT-TERM MEMORY
# ================================
if LEGACY_MEMORY_API:
    short_term_memory = ShortTermMemory(
        storage=RAGStorage(
            type="short_term",
            embedder_config=_embedder_config(),
        )
    )
else:
    short_term_memory = Memory(
        storage="lancedb",
        embedder=memory_embedder(),
        root_scope="/short_term",
    )


# ================================
# LONG-TERM MEMORY
# ================================
if LEGACY_MEMORY_API:
    long_term_memory = LongTermMemory(
        storage=LTMSQLiteStorage(
            db_path="memory/long_term_memory.db",
        )
    )
else:
    long_term_memory = Memory(
        storage="lancedb",
        embedder=memory_embedder(),
        root_scope="/long_term",
    )


# ================================
# ENTITY MEMORY
# ================================
if LEGACY_MEMORY_API:
    entity_memory = EntityMemory(
        storage=RAGStorage(
            type="entities",
            embedder_config=_embedder_config(),
        )
    )
else:
    entity_memory = Memory(
        storage="lancedb",
        embedder=memory_embedder(),
        root_scope="/entities",
    )
