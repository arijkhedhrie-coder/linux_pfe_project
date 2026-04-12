import json
import logging
import re
from dataclasses import dataclass
from typing import Literal

import pandas as pd

from config.config import SERVEUR_NOM, ANNEE
from src.adapter import normalize


# ───────────────────────── Logging structuré ─────────────────────────
logger = logging.getLogger("transformer")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)


def log_event(level: int, event: str, **fields):
    payload = {"event": event, **fields}
    logger.log(level, json.dumps(payload, ensure_ascii=False))


# ───────────────────────── Types / Config ─────────────────────────
_REQUIRED_NORMALIZE = ("timestamp", "Content")


@dataclass(frozen=True)
class TransformerConfig:
    serveur_nom: str = SERVEUR_NOM
    annee: str = str(ANNEE)


DatasetKind = Literal["structured", "canonical", "unknown"]


# ───────────────────────── Utilitaires ─────────────────────────
def detecter_etat(message) -> str:
    message = str(message).lower()
    if any(mot in message for mot in [
        "failed", "error", "critical", "denied",
        "invalid", "refused", "killed", "failure",
        "authentication failure", "unknown",
    ]):
        return "Error"
    if any(mot in message for mot in ["warning", "warn", "timeout", "retry"]):
        return "Warning"
    return "Info"


def extraire_ip(message) -> str | None:
    ip = re.search(r"\b(\d{1,3}\.){3}\d{1,3}\b", str(message))
    return ip.group(0) if ip else None


def ensure_columns(df: pd.DataFrame, cols: tuple[str, ...], where: str) -> None:
    missing = [c for c in cols if c not in df.columns]
    if missing:
        raise ValueError(f"[transformer] missing={missing} in {where}. cols={list(df.columns)}")


# ───────────────────────── 1) Ingestion (détection + scoring) ─────────────────────────
def structured_confidence(df: pd.DataFrame) -> float:
    """
    Score 0..1: mesure à quel point le DF ressemble à un dataset structuré “Linux_2k”.
    Pas binaire: on combine présence + qualité minimale.
    """
    if df is None or df.empty:
        return 0.0

    required = ["Content", "Component"]
    time_triplet = ["Month", "Date", "Time"]
    has_required = sum(int(c in df.columns) for c in required) / len(required)
    has_time = 1.0 if all(c in df.columns for c in time_triplet) or ("DateTime" in df.columns) else 0.0

    # qualité: % non-null dans Content/Component
    quality = 0.0
    if "Content" in df.columns:
        quality += float(df["Content"].notna().mean())
    if "Component" in df.columns:
        quality += float(df["Component"].notna().mean())
    quality = quality / 2.0 if quality else 0.0

    score = 0.45 * has_required + 0.25 * has_time + 0.30 * quality
    return round(max(0.0, min(1.0, score)), 3)


def classify_dataset(df: pd.DataFrame, threshold: float = 0.7) -> tuple[DatasetKind, float]:
    score = structured_confidence(df)
    kind: DatasetKind = "structured" if score >= threshold else "unknown"
    return kind, score


# ───────────────────────── 2) Transformation (canonical → normalize) ─────────────────────────
def structured_to_canonical(df: pd.DataFrame, cfg: TransformerConfig) -> pd.DataFrame:
    df = df.copy()

    if {"Month", "Date", "Time"}.issubset(df.columns):
        dt = (
            df["Month"].astype(str) + " " +
            df["Date"].astype(str) + " " +
            cfg.annee + " " +
            df["Time"].astype(str)
        )
        timestamp = pd.to_datetime(dt, format="mixed", errors="coerce")
    else:
        timestamp = pd.to_datetime(df.get("DateTime"), errors="coerce")

    canonical = pd.DataFrame({
        "timestamp": timestamp,
        "source_log": df.get("Component", pd.Series(["unknown"] * len(df))).astype(str),
        "Content": df.get("Content", pd.Series([""] * len(df))).astype(str),
        "type_event": df.get("EventId", pd.Series(["UNKNOWN"] * len(df))).astype(str),
        "source_ip": df.get("IP_Source"),
    })

    if "DatasetSource" in df.columns:
        canonical["DatasetSource"] = df["DatasetSource"].reset_index(drop=True)

    return canonical


def normalize_checked(df_in: pd.DataFrame) -> pd.DataFrame:
    df_norm = normalize(df_in.reset_index(drop=True), verbose=False)
    ensure_columns(df_norm, _REQUIRED_NORMALIZE, where="normalize() output")
    return df_norm


def norm_to_clean(df_norm: pd.DataFrame, cfg: TransformerConfig) -> pd.DataFrame:
    # colonnes optionnelles sécurisées
    source_log = df_norm["source_log"] if "source_log" in df_norm.columns else pd.Series(["unknown"] * len(df_norm))
    type_event = df_norm["type_event"] if "type_event" in df_norm.columns else pd.Series(["UNKNOWN"] * len(df_norm))
    source_ip = df_norm["source_ip"] if "source_ip" in df_norm.columns else pd.Series([None] * len(df_norm))

    df_clean = pd.DataFrame()
    df_clean["Date"] = pd.to_datetime(df_norm["timestamp"], errors="coerce")
    df_clean["Serveur"] = cfg.serveur_nom
    df_clean["Service"] = source_log.fillna("unknown").astype(str)
    df_clean["Message"] = df_norm["Content"].astype(str)
    df_clean["EventId"] = type_event.fillna("UNKNOWN").astype(str)
    df_clean["Etat"] = df_clean["Message"].apply(detecter_etat)

    # IP: garder l’IP existante, sinon fallback regex
    df_clean["IP_Source"] = source_ip.where(source_ip.notna(), df_clean["Message"].apply(extraire_ip))

    if "DatasetSource" in df_norm.columns:
        df_clean["DatasetSource"] = df_norm["DatasetSource"].reset_index(drop=True)

    return df_clean


# ───────────────────────── 3) Validation (sortie stable) ─────────────────────────
def validate_clean(df_clean: pd.DataFrame) -> None:
    ensure_columns(df_clean, ("Date", "Serveur", "Service", "Message", "EventId", "Etat", "IP_Source"), where="df_clean")


# ───────────────────────── API principale ─────────────────────────
def transformer(df: pd.DataFrame, cfg: TransformerConfig | None = None) -> pd.DataFrame:
    cfg = cfg or TransformerConfig()

    if df is None or len(df) == 0:
        return pd.DataFrame(columns=["Date", "Serveur", "Service", "Message", "EventId", "Etat", "IP_Source"])

    kind, score = classify_dataset(df, threshold=0.7)
    log_event(logging.INFO, "dataset_classified", kind=kind, confidence=score, rows=int(len(df)), cols=int(len(df.columns)))

    if kind == "structured":
        df_in = structured_to_canonical(df, cfg)
        log_event(logging.INFO, "structured_wrapped_to_canonical", rows=int(len(df_in)))
    else:
        df_in = df

    df_norm = normalize_checked(df_in)
    log_event(logging.INFO, "normalized", rows=int(len(df_norm)), cols=int(len(df_norm.columns)))

    df_clean = norm_to_clean(df_norm, cfg)
    validate_clean(df_clean)
    log_event(logging.INFO, "transformed", rows=int(len(df_clean)))

    return df_clean