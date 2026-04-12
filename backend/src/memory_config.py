

from __future__ import annotations

from crewai.memory import EntityMemory, ShortTermMemory, LongTermMemory
from crewai.memory.storage.rag_storage import RAGStorage
from crewai.memory.storage.ltm_sqlite_storage import LTMSQLiteStorage


def _ollama_available() -> bool:
    try:
        import ollama  # noqa: F401
        return True
    except Exception:
        return False


USE_OLLAMA = _ollama_available()

# ================================
# SHORT-TERM MEMORY
# ================================
# Point fort binôme: embeddings 100% local via Ollama
short_term_memory = ShortTermMemory(
    storage=RAGStorage(
        type="short_term",
        embedder_config=(
            {
                "provider": "ollama",
                "config": {
                    "model": "nomic-embed-text",
                    "base_url": "http://localhost:11434",
                },
            }
            if USE_OLLAMA
            else {
                "provider": "huggingface",
                "config": {"model": "sentence-transformers/all-MiniLM-L6-v2"},
            }
        ),
    )
)

# ================================
# LONG-TERM MEMORY (SQLite persistant)
# ================================
long_term_memory = LongTermMemory(
    storage=LTMSQLiteStorage(
        db_path="memory/long_term_memory.db",
    )
)

# ================================
# ENTITY MEMORY (serveurs, IPs, services…)
# ================================
entity_memory = EntityMemory(
    storage=RAGStorage(
        type="entities",
        embedder_config=(
            {
                "provider": "ollama",
                "config": {
                    "model": "nomic-embed-text",
                    "base_url": "http://localhost:11434",
                },
            }
            if USE_OLLAMA
            else {
                "provider": "huggingface",
                "config": {"model": "sentence-transformers/all-MiniLM-L6-v2"},
            }
        ),
    )
)