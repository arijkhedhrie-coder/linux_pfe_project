"""
main.py — VERSION COMPLÈTE FINALE (HYBRID v3 + robustesse prod-lite)

Pipeline:
  1) Ingestion S3 (processed/dataset_*.csv) — tolérant aux fichiers corrompus
  2) Normalisation schéma (Date/IP/Etat/Service/Message) — testable
  3) Métriques + résumé compact pour agents
  4) PASS 1 détection (seuils par défaut)
  5) Orchestrateur → DynamicConfig (JSON)
  6) PASS 2 détection (si config non-default)
  7) Agents CrewAI:
       - Crew A: collect/analyse/detect (tâches conditionnelles)
       - Crew B: reporter (séparé pour résilience)
     + filets outils: correctif + rapport (si besoin)
  8) Forecast (best-effort) + sauvegarde locale (protégée) + S3 (best-effort) + mémoire

Points forts:
  - Fix SSL: httpx/http2 désactivé
  - Throttle LLM défensif: jamais `raise None`
  - S3: try/catch par objet
  - Etat: mapping statut/severite/message (évite régression "Info" aveugle)
  - Mémoire: ips_suspectes calculés
  - Import détection: message explicite si ml_engine_bridge ET anomaly_detection échouent
"""

from __future__ import annotations

import io
import json
import logging
import os
import sys
import time
import inspect
from datetime import datetime
from typing import Any

import boto3
import pandas as pd
from botocore.config import Config as BotoConfig
from dotenv import load_dotenv

# ─────────────────────────────────────────────────────────────────────────────
# UTF-8 console (Windows)
# ─────────────────────────────────────────────────────────────────────────────
os.environ.setdefault("PYTHONIOENCODING", "utf-8")
os.environ.setdefault("PYTHONUTF8", "1")
try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

load_dotenv()

# ─────────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────────
LOG = logging.getLogger("main")
if not LOG.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    LOG.addHandler(h)
LOG.setLevel(logging.INFO)

# ─────────────────────────────────────────────────────────────────────────────
# CrewAI storage
# ─────────────────────────────────────────────────────────────────────────────
if "CREWAI_STORAGE_DIR" not in os.environ:
    os.environ["CREWAI_STORAGE_DIR"] = os.path.join(os.getcwd(), ".crewai")
os.makedirs(os.environ["CREWAI_STORAGE_DIR"], exist_ok=True)

# ─────────────────────────────────────────────────────────────────────────────
# FIX SSL / HTTP2
# ─────────────────────────────────────────────────────────────────────────────
try:
    import httpx
    import litellm

    litellm.client_session = httpx.Client(verify=True, http2=False, timeout=60.0)
    LOG.info("Fix SSL appliqué — HTTP/2 désactivé, timeout=60s")
except Exception as e:
    LOG.warning("Fix SSL non appliqué: %s: %s", type(e).__name__, e)

# ─────────────────────────────────────────────────────────────────────────────
# Patch Chroma/Ollama (best-effort)
# ─────────────────────────────────────────────────────────────────────────────
try:
    from chromadb.utils.embedding_functions.ollama_embedding_function import OllamaEmbeddingFunction
    import crewai.rag.chromadb.config as _chroma_cfg

    def _ollama_ef():
        return OllamaEmbeddingFunction(
            model_name="nomic-embed-text",
            url="http://localhost:11434/api/embeddings",
        )

    _chroma_cfg.ChromaDBConfig._default_embedding_function = staticmethod(_ollama_ef)
    LOG.info("Patch ChromaDB Ollama appliqué")
except Exception as e:
    LOG.warning("Patch ChromaDB ignoré: %s: %s", type(e).__name__, e)

try:
    from crewai.memory.storage.rag_storage import RAGStorage

    _orig_rag_init = RAGStorage.__init__

    def _patched_rag_init(self, *args, **kwargs):
        kwargs["embedder_config"] = {
            "provider": "ollama",
            "config": {"model": "nomic-embed-text", "base_url": "http://localhost:11434"},
        }
        return _orig_rag_init(self, *args, **kwargs)

    RAGStorage.__init__ = _patched_rag_init
    LOG.info("Patch RAGStorage Ollama appliqué")
except Exception as e:
    LOG.warning("Patch RAGStorage ignoré: %s: %s", type(e).__name__, e)

# ─────────────────────────────────────────────────────────────────────────────
# Imports métier
# ─────────────────────────────────────────────────────────────────────────────
from src.metriques import calculer_metriques, get_summary_for_detector
from src.upload_s3 import sauvegarder_localement, uploader_vers_s3
from src.agents.memory import sauvegarder_memoire, get_contexte_historique
from src.hybrid_config import DynamicConfig

# Détection: supporte 2 layouts possibles + erreur explicite si tout échoue
_detect_fn = None
_get_agent_inputs_fn = None
_retrain_fn = None

_err_ml: BaseException | None = None
try:
    from src.ml_engine_bridge import detecter_anomalies as _detect_fn  # type: ignore
    from src.ml_engine_bridge import get_agent_inputs as _get_agent_inputs_fn  # type: ignore
    from src.ml_engine_bridge import reentralner_avec_nouveaux_logs as _retrain_fn  # type: ignore
except Exception as e:
    _err_ml = e
    _err_ad: BaseException | None = None
    try:
        from src.anomaly_detection import detecter_anomalies as _detect_fn  # type: ignore
        from src.anomaly_detection import reentralner_avec_nouveaux_logs as _retrain_fn  # type: ignore

        def _get_agent_inputs_fn(alarmes, anomalies):  # type: ignore
            return {
                "nb_anomalies": str(len(anomalies) if isinstance(anomalies, pd.DataFrame) else 0),
                "alarmes_resumees": (
                    json.dumps(alarmes[:5], ensure_ascii=False)
                    if isinstance(alarmes, list)
                    else str(alarmes)[:800]
                ),
                "ip_principale": "N/A",
                "chain_incidents": "0",
                "corr_incidents": "0",
            }
    except Exception as e2:
        _err_ad = e2
        LOG.error("Import détection: ml_engine_bridge a échoué: %s: %s", type(_err_ml).__name__, _err_ml)
        LOG.error("Import détection: anomaly_detection a échoué: %s: %s", type(_err_ad).__name__, _err_ad)
        raise ImportError(
            "Impossible de charger la détection: ni `src.ml_engine_bridge` ni `src.anomaly_detection` "
            "n'est importable. Vérifie l'arborescence `src/`, les noms de modules, et les dépendances."
        ) from (_err_ad if _err_ml is None else _err_ml)


def _call_detecter_anomalies(df_in: pd.DataFrame, dynamic_config: Any | None):
    """
    Compatibilité entre versions de `detecter_anomalies`:
    - certaines signatures n'acceptent pas `dynamic_config`
    - certaines attendent un autre nom (`config`, `cfg`, etc.)

    Stratégie:
    - bind via `inspect.signature` (robuste)
    - si Pass2 demandé mais aucun param compatible: warning + appel Pass1-equivalent
    """
    fn = _detect_fn
    try:
        sig = inspect.signature(fn)
    except Exception:
        return fn(df_in)

    params = sig.parameters
    bound = sig.bind_partial()

    # 1) bind dataframe (df / df_clean / df_multi / df_par_ip / premier arg non-self)
    df_keys = ("df", "df_clean", "df_multi", "df_logs", "dataframe", "df_par_ip")
    bound_df = False
    for k in df_keys:
        if k in params:
            bound.arguments[k] = df_in
            bound_df = True
            break

    if not bound_df:
        positional = [
            name
            for name, p in params.items()
            if p.kind
            in (
                inspect.Parameter.POSITIONAL_ONLY,
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
            )
        ]
        # skip self
        if positional and positional[0] == "self":
            positional = positional[1:]
        if positional:
            bound.arguments[positional[0]] = df_in
            bound_df = True

    if not bound_df:
        # dernier recours: 1er argument positionnel
        return fn(df_in)

    # 2) bind dynamic config si possible
    dc_keys = [
        "dynamic_config",
        "dynamic",
        "dyn_cfg",
        "cfg",
        "config",
        "agent_config",
        "hybrid_config",
    ]
    dc_param = next((k for k in dc_keys if k in params), None)

    if dynamic_config is not None and dc_param is None:
        LOG.warning(
            "PASS2: `detecter_anomalies` n'accepte pas de dynamic config (signature=%s) — "
            "Pass2 ignoré côté détecteur (alarmes = Pass1).",
            str(sig),
        )

    if dc_param is not None and dynamic_config is not None:
        bound.arguments[dc_param] = dynamic_config

    try:
        return fn(*bound.args, **bound.kwargs)
    except TypeError:
        # si bind_partial n'arrive pas à couvrir des cas exotiques, fallback
        if dynamic_config is None:
            return fn(df_in)
        LOG.warning("Detect: bind failed; fallback positional df only. sig=%s", str(sig))
        return fn(df_in)

# SessionLogger (stub si absent)
try:
    from src.logging_utils import SessionLogger
except Exception:

    class SessionLogger:  # type: ignore
        def pipeline_start(self, **kwargs):
            LOG.info("pipeline_start %s", kwargs)

        def metrics_computed(self, summary):
            LOG.info("metrics_computed %s", summary)

        def pass1_complete(self, alarmes, **kwargs):
            LOG.info("pass1_complete alarms=%s", len(alarmes) if hasattr(alarmes, "__len__") else "n/a")

        def pass2_complete(self, alarmes_final, alarmes_pass1, **kwargs):
            LOG.info("pass2_complete final=%s pass1=%s", len(alarmes_final), len(alarmes_pass1))

        def dynamic_config_default(self):
            LOG.info("dynamic_config_default")

        def dynamic_config_issued(self, cfg):
            try:
                LOG.info("dynamic_config_issued %s", cfg.summary())
            except Exception:
                LOG.info("dynamic_config_issued %s", str(cfg))

        def agents_complete(self, txt: str):
            LOG.info("agents_complete len=%s", len(txt or ""))

        def warning(self, where: str, msg: str):
            LOG.warning("[%s] %s", where, msg)

        def error(self, where: str, exc: BaseException):
            LOG.exception("[%s] %s", where, exc)

        def session_summary(self, **kwargs):
            LOG.info("session_summary keys=%s", list(kwargs.keys()))

        def close(self):
            return

# CrewAI
try:
    from crewai import Crew, Process

    CREWAI_AVAILABLE = True
    _CREWAI_IMPORT_ERR = None
except Exception as e:
    CREWAI_AVAILABLE = False
    _CREWAI_IMPORT_ERR = e

if CREWAI_AVAILABLE:
    from src.agents.agents import (
        collector_agent,
        analyst_agent,
        detector_agent,
        reporter_agent,
        orchestrator_agent,
        outil_correctif,
        outil_rapport,
        llm as groq_llm,
    )
    from src.agents.tasks import (
        tache_collecte,
        tache_analyse,
        tache_dynamic_config,
        tache_rapport,
        creer_tache_detection,
        creer_tache_correction,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Normalisation (testable)
# ─────────────────────────────────────────────────────────────────────────────
def _map_etat_from_row(row: pd.Series) -> str:
    if "Etat" in row.index and pd.notna(row.get("Etat")) and str(row["Etat"]).strip():
        return str(row["Etat"])

    if "statut" in row.index and pd.notna(row.get("statut")):
        v = str(row["statut"]).lower()
        if any(k in v for k in ["error", "failed", "critical", "denied", "refused", "failure"]):
            return "Error"
        if any(k in v for k in ["warning", "warn", "timeout"]):
            return "Warning"
        return "Info"

    if "severite" in row.index and pd.notna(row.get("severite")):
        v = str(row["severite"]).lower()
        if v in ["critical", "error", "high"]:
            return "Error"
        if v in ["warning", "medium"]:
            return "Warning"
        return "Info"

    msg = str(row.get("Message", row.get("detail", ""))).lower()
    if any(k in msg for k in ["error", "failed", "critical", "denied", "refused", "failure"]):
        return "Error"
    if any(k in msg for k in ["warning", "warn", "timeout"]):
        return "Warning"
    return "Info"


def normalize_logs_df(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()

    if "Date" not in df.columns:
        for col in ("timestamp", "DateTime"):
            if col in df.columns:
                df["Date"] = pd.to_datetime(df[col], errors="coerce")
                break
        else:
            df["Date"] = pd.Timestamp.now()
    else:
        df["Date"] = pd.to_datetime(df["Date"], errors="coerce")

    if "IP_Source" not in df.columns:
        df["IP_Source"] = df.get("source_ip", None)

    if "Service" not in df.columns:
        df["Service"] = df.get("source_log", df.get("type_event", "unknown"))

    if "Message" not in df.columns:
        df["Message"] = df.get("detail", "").astype(str)

    df["Etat"] = df.apply(_map_etat_from_row, axis=1)
    return df.dropna(subset=["Date"])


def build_ip_feature_frame(df_logs: pd.DataFrame) -> pd.DataFrame:
    """
    `src.anomaly_detection.detecter_anomalies` attend un DataFrame **par IP** avec colonnes numériques:
      - Nombre_Tentatives (obligatoire pour FEATURES)
      - Nombre_Erreurs / nb_warnings (optionnel mais utile)

    À partir des logs bruts (une ligne = un événement), on agrège par `IP_Source`.
    """
    if "IP_Source" not in df_logs.columns:
        raise ValueError("Colonne IP_Source absente — impossible d'agréger par IP.")

    df = df_logs[df_logs["IP_Source"].notna()].copy()
    if df.empty:
        return pd.DataFrame(columns=["IP_Source", "Nombre_Tentatives", "Nombre_Erreurs", "nb_warnings", "Date"])

    if "Etat" not in df.columns:
        df["Etat"] = "Info"

    df["Date"] = pd.to_datetime(df.get("Date"), errors="coerce")

    g = df.groupby("IP_Source", dropna=True)
    out = g.agg(
        Nombre_Tentatives=("Etat", "size"),
        Nombre_Erreurs=("Etat", lambda s: int((s == "Error").sum())),
        nb_warnings=("Etat", lambda s: int((s == "Warning").sum())),
        Date=("Date", "max"),
    ).reset_index()

    # Signal "tentatives" vu par le modèle:
    # - max(total_events, error_events) évite les vecteurs à 0 si beaucoup de lignes sont "Info"
    out["Nombre_Tentatives"] = out[["Nombre_Tentatives", "Nombre_Erreurs"]].max(axis=1).astype(int)

    out = out.sort_values(["Nombre_Erreurs", "Nombre_Tentatives"], ascending=False).reset_index(drop=True)
    return out


def load_logs_from_s3(prefix: str = "processed/dataset_") -> pd.DataFrame:
    bucket = os.environ.get("S3_BUCKET_NAME", "")
    region = os.environ.get("AWS_REGION", "us-east-1")
    if not bucket:
        raise RuntimeError("Missing S3_BUCKET_NAME")

    boto_cfg = BotoConfig(
        retries={"max_attempts": 8, "mode": "adaptive"},
        connect_timeout=int(os.getenv("AWS_S3_CONNECT_TIMEOUT", "10")),
        read_timeout=int(os.getenv("AWS_S3_READ_TIMEOUT", "300")),
        max_pool_connections=32,
    )

    s3 = boto3.client(
        "s3",
        region_name=region,
        aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY"),
        config=boto_cfg,
    )

    resp = s3.list_objects_v2(Bucket=bucket, Prefix=prefix)
    objects = resp.get("Contents", []) or []
    if not objects:
        raise RuntimeError(f"No datasets found in s3://{bucket}/{prefix}")

    frames: list[pd.DataFrame] = []
    for obj in objects:
        key = obj["Key"]
        try:
            body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
            df_tmp = pd.read_csv(io.BytesIO(body))
            server_name = key.split("/")[-1].replace("dataset_", "").replace(".csv", "")
            df_tmp["Serveur"] = f"server_{server_name}"
            frames.append(df_tmp)
            LOG.info("S3 OK %s rows=%s", key, len(df_tmp))
        except Exception as e:
            LOG.warning("S3 SKIP %s: %s: %s", key, type(e).__name__, e)

    if not frames:
        raise RuntimeError("[S3] All dataset loads failed.")

    df = pd.concat(frames, ignore_index=True)
    df = normalize_logs_df(df)
    LOG.info("S3 merged rows=%s", len(df))
    return df


def _ips_suspectes(df: pd.DataFrame, anomalies: Any, k: int = 5) -> list[str]:
    ips: list[str] = []

    if isinstance(anomalies, pd.DataFrame) and (not anomalies.empty) and "source_ip" in anomalies.columns:
        ips.extend(anomalies["source_ip"].dropna().astype(str).head(k).tolist())

    if len(ips) < k and "IP_Source" in df.columns:
        tmp = df[df["IP_Source"].notna()].copy()
        if not tmp.empty:
            scores = (
                tmp.groupby("IP_Source")["Etat"]
                .apply(lambda s: int((s == "Error").sum()))
                .sort_values(ascending=False)
            )
            for ip in scores.head(k).index.astype(str).tolist():
                if ip not in ips:
                    ips.append(ip)
                if len(ips) >= k:
                    break

    return ips[:k]


def _install_llm_throttle() -> None:
    if not CREWAI_AVAILABLE:
        return

    _last = [0.0]
    _orig = groq_llm.__class__.call

    def _throttled_call(self, *args, **kwargs):
        elapsed = time.time() - _last[0]
        if elapsed < 25:
            time.sleep(25 - elapsed)
        _last[0] = time.time()

        last_exc: BaseException | None = None
        for attempt in range(3):
            try:
                return _orig(self, *args, **kwargs)
            except BaseException as e:
                last_exc = e
                s = str(e).lower()

                if "429" in s or "rate_limit" in s:
                    wait = 30 + attempt * 15
                    LOG.warning("THROTTLE rate_limit (%s/3) sleep=%ss", attempt + 1, wait)
                    time.sleep(wait)
                elif any(k in s for k in ["ssl", "eof", "unexpected_eof", "connecterror", "broken pipe", "reset"]):
                    wait = 15 + attempt * 10
                    LOG.warning("THROTTLE ssl/eof (%s/3) sleep=%ss + new httpx client", attempt + 1, wait)
                    try:
                        litellm.client_session = httpx.Client(verify=True, http2=False, timeout=60.0)
                    except Exception:
                        pass
                    time.sleep(wait)
                else:
                    LOG.warning("THROTTLE other (%s/3): %s: %s", attempt + 1, type(e).__name__, e)
                    time.sleep(8)

        if last_exc is None:
            raise RuntimeError("LLM call failed after retries, but no exception was captured (unexpected).")
        raise last_exc

    groq_llm.__class__.call = _throttled_call  # type: ignore[attr-defined]


def _run_dynamic_config(log: SessionLogger, agent_inputs: dict) -> DynamicConfig:
    if not CREWAI_AVAILABLE:
        log.warning("crewai", f"CrewAI indisponible: {_CREWAI_IMPORT_ERR}")
        return DynamicConfig.default()

    _install_llm_throttle()

    LOG.info("HYBRID Step 5 — Orchestrator → DynamicConfig")
    try:
        crew = Crew(
            agents=[orchestrator_agent],
            tasks=[tache_dynamic_config],
            process=Process.sequential,
            memory=False,
            verbose=True,
        )
        out = crew.kickoff(inputs=agent_inputs)
        cfg = DynamicConfig.from_json(str(out))
        cfg.issued_by = "orchestrator_agent"
        log.dynamic_config_issued(cfg)
        return cfg
    except Exception as e:
        log.warning("dynamic_config", f"{type(e).__name__}: {e} — defaults")
        return DynamicConfig.default()

def main() -> None:
    log = SessionLogger()

    # Flag métier (si présent dans ton module agents)
    try:
        import src.agents.agents as _agents_module

        _agents_module._alarme_declenchee_ce_cycle = False  # type: ignore[attr-defined]
    except Exception:
        pass

    resultat = ""
    threshold_snapshots: list[Any] = []
    pass2_ran = False

    try:
        LOG.info("PIPELINE START")
        df = load_logs_from_s3()

        log.pipeline_start(
            row_count=len(df),
            server_count=int(df["Serveur"].nunique()) if "Serveur" in df.columns else 0,
            data_sources=df["Serveur"].unique().tolist() if "Serveur" in df.columns else [],
        )

        # Step 2 — metrics
        erreurs_par_heure, tentatives_par_ip, events_par_service = calculer_metriques(df)
        metrics_summary = get_summary_for_detector(erreurs_par_heure, tentatives_par_ip, df_clean=df)
        log.metrics_computed(metrics_summary)

        # Forecast best-effort
        try:
            from src.forecasting import prevoir_erreurs

            _ = prevoir_erreurs(erreurs_par_heure)
        except Exception as e:
            log.warning("forecast", f"skipped: {type(e).__name__}: {e}")

        # Features agrégées (par IP) — nécessaire pour `src.anomaly_detection.detecter_anomalies`
        # Step 3 — PASS 1
        LOG.info("PASS 1 — default thresholds")
        df_ip = build_ip_feature_frame(df)
        df_annot, anomalies, alarmes_pass1, threshold_snapshots = _call_detecter_anomalies(df_ip, dynamic_config=None)
        log.pass1_complete(alarmes_pass1, threshold_snapshot=threshold_snapshots[0] if threshold_snapshots else None)

        # Step 4 — agent inputs
        sources_str = ",".join(df["Serveur"].unique().tolist()) if "Serveur" in df.columns else "unknown"
        agent_inputs = _get_agent_inputs_fn(alarmes_pass1, anomalies)  # type: ignore[misc]
        agent_inputs.update(
            {
                "serveur_nom": sources_str,
                "date": datetime.now().strftime("%Y%m%d_%H%M%S"),
                "historical_context": get_contexte_historique(),
                **{k: str(v) for k, v in metrics_summary.items()},
                "pass2_ran": "False",
                "dynamic_config_summary": "not yet computed",
                "dynamic_config_reasoning": "not yet computed",
            }
        )

        # Step 5 — orchestrator
        dynamic_config = _run_dynamic_config(log, agent_inputs)

        # Step 6 — PASS 2
        if not dynamic_config.is_default():
            LOG.info("PASS 2 — agent-adjusted thresholds")
            df_annot, anomalies, alarmes_final, threshold_snapshots = _call_detecter_anomalies(df_ip, dynamic_config=dynamic_config)
            log.pass2_complete(alarmes_final, alarmes_pass1, threshold_snapshot=threshold_snapshots[-1] if threshold_snapshots else None)
            pass2_ran = True
        else:
            log.dynamic_config_default()
            alarmes_final = alarmes_pass1
            pass2_ran = False

        agent_inputs.update(_get_agent_inputs_fn(alarmes_final, anomalies))  # type: ignore[misc]
        agent_inputs.update(
            {
                "pass2_ran": str(pass2_ran),
                "dynamic_config_summary": dynamic_config.summary(),
                "dynamic_config_reasoning": (dynamic_config.reasoning or "")[:200],
            }
        )

        parts: list[str] = []

        if not CREWAI_AVAILABLE:
            resultat = f"CrewAI skipped: {_CREWAI_IMPORT_ERR}"
            log.warning("crewai", resultat)
        else:
            nb_anomalies = int(str(agent_inputs.get("nb_anomalies", "0") or "0"))
            ip_principale = str(agent_inputs.get("ip_principale", "N/A") or "N/A")
            alarmes_resumees = str(agent_inputs.get("alarmes_resumees", "Aucune") or "Aucune")

            t_detection = creer_tache_detection(nb_anomalies, ip_principale, alarmes_resumees)

            # Crew A — analyse
            analysis_crew = Crew(
                agents=[collector_agent, analyst_agent, detector_agent],
                tasks=[tache_collecte, tache_analyse, t_detection],
                process=Process.sequential,
                memory=False,
                verbose=True,
            )

            try:
                crew_out = analysis_crew.kickoff(inputs=agent_inputs)
                parts.append(str(crew_out))
            except Exception as e:
                log.warning("analysis_crew", f"{type(e).__name__}: {e}")
                parts.append(f"[PARTIAL] analysis_crew: {type(e).__name__}: {e}")

            # Crew B — rapport (résilience)
            report_crew = Crew(
                agents=[reporter_agent],
                tasks=[tache_rapport],
                process=Process.sequential,
                memory=False,
                verbose=True,
            )
            try:
                report_out = report_crew.kickoff(inputs=agent_inputs)
                parts.append(f"[REPORT_AGENT]\n{report_out}")
            except Exception as e:
                log.warning("report_crew", f"{type(e).__name__}: {e}")
                parts.append(f"[REPORT_AGENT][WARN] {type(e).__name__}: {e}")

            # Filet outil correctif
            try:
                _ = creer_tache_correction(nb_anomalies, ip_principale)  # garde cohérence si tu relies sur la factory
                corr_in = f"BLOCAGE IP {ip_principale} brute-force SSH critique"
                corr = outil_correctif._run(anomalie_json=corr_in)
                parts.append(f"[CORRECTIVE_TOOL]\n{corr}")
            except Exception as e:
                parts.append(f"[CORRECTIVE_TOOL][WARN] {type(e).__name__}: {e}")

            # Filet outil rapport
            try:
                report_payload = json.dumps(
                    {
                        "health": agent_inputs.get("health_score"),
                        "anomalies": agent_inputs.get("nb_anomalies"),
                        "pattern": agent_inputs.get("attack_pattern"),
                        "ip": agent_inputs.get("ip_principale"),
                        "chains": agent_inputs.get("chain_incidents"),
                        "pass2": agent_inputs.get("pass2_ran"),
                        "timestamp": agent_inputs.get("date"),
                    },
                    ensure_ascii=False,
                )
                rep = outil_rapport._run(rapport_json=report_payload)
                parts.append(f"[REPORT_TOOL]\n{rep}")
            except Exception as e:
                parts.append(f"[REPORT_TOOL][WARN] {type(e).__name__}: {e}")

            resultat = "\n\n".join(parts)
            log.agents_complete(resultat)

        # Step 8 — retrain + persist + memory
        try:
            _retrain_fn(df_ip)  # type: ignore[misc]
        except Exception as e:
            log.warning("retrain", f"{type(e).__name__}: {e}")

        try:
            sauvegarder_localement(df, erreurs_par_heure, tentatives_par_ip, events_par_service)
        except Exception as e:
            log.warning("save_local", f"{type(e).__name__}: {e}")

        try:
            uploader_vers_s3()
        except Exception as e:
            log.warning("upload_s3", f"{type(e).__name__}: {e}")

        sauvegarder_memoire(
            {
                "ips_suspectes": _ips_suspectes(df, anomalies, k=5),
                "nb_anomalies": len(anomalies) if isinstance(anomalies, pd.DataFrame) else int(str(agent_inputs.get("nb_anomalies", "0") or "0")),
                "nb_alarmes_pass1": len(alarmes_pass1) if hasattr(alarmes_pass1, "__len__") else 0,
                "nb_alarmes_final": len(alarmes_final) if hasattr(alarmes_final, "__len__") else 0,
                "health_score": metrics_summary.get("health_score", 100.0),
                "attack_pattern": metrics_summary.get("attack_pattern", "unknown"),
                "dynamic_config": dynamic_config.to_json(),
                "agent_threat_level": getattr(dynamic_config, "threat_level", "NORMAL"),
                "pass2_ran": pass2_ran,
                "threshold_snapshots": threshold_snapshots,
                "date": agent_inputs.get("date"),
                "alarmes": alarmes_final,
                "resultat_agents": str(resultat)[:500],
            }
        )

        LOG.info("MEMORY ctx=%s", get_contexte_historique())

        log.session_summary(
            alarmes_pass1=alarmes_pass1,
            alarmes_final=alarmes_final,
            threshold_snapshots=threshold_snapshots,
            metrics=metrics_summary,
            dynamic_config=dynamic_config,
        )

        LOG.info("PIPELINE DONE")
        print(resultat)

    except Exception as exc:
        log.error("main", exc)
        raise
    finally:
        log.close()


if __name__ == "__main__":
    main()
    os._exit(0)