

from __future__ import annotations

import json
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable

from config.config import BUCKET_NAME, AWS_REGION, AWS_ACCESS_KEY, AWS_SECRET_KEY


logger = logging.getLogger("upload_s3")
if not logger.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    logger.addHandler(h)
logger.setLevel(logging.INFO)

_BACKEND_ROOT = Path(__file__).resolve().parents[1]
_DEFAULT_OUTPUT_DIR = _BACKEND_ROOT / "output"


def _resolve_output_dir(out_dir: str | os.PathLike[str] | None) -> Path:
    if out_dir is None:
        return _DEFAULT_OUTPUT_DIR
    candidate = Path(out_dir)
    if not candidate.is_absolute():
        candidate = _BACKEND_ROOT / candidate
    return candidate


@dataclass(frozen=True)
class UploadResult:
    key: str
    status: str
    message: str = ""
    size_bytes: int | None = None
    duration_s: float | None = None
    mbs: float | None = None


def sauvegarder_localement(
    df_clean,
    erreurs_par_heure,
    tentatives_par_ip,
    events_par_service,
    out_dir: str | os.PathLike[str] | None = None,
) -> None:
    resolved_out_dir = _resolve_output_dir(out_dir)
    os.makedirs(resolved_out_dir, exist_ok=True)
    df_clean.to_csv(resolved_out_dir / "logs_clean.csv", index=False)
    erreurs_par_heure.to_csv(resolved_out_dir / "erreurs_par_heure.csv", index=False)
    tentatives_par_ip.to_csv(resolved_out_dir / "tentatives_par_ip.csv", index=False)
    events_par_service.to_csv(resolved_out_dir / "events_par_service.csv", index=False)
    logger.info("Fichiers sauvegardés localement (%s)", resolved_out_dir)


def _build_s3_client(connect_timeout_s: int, read_timeout_s: int):
    try:
        import boto3
        from botocore.config import Config
    except Exception as e:
        return None, f"boto3 indisponible: {type(e).__name__}: {e}"

    cfg = Config(
        connect_timeout=connect_timeout_s,
        read_timeout=read_timeout_s,
        retries={"max_attempts": 3, "mode": "adaptive"},
        max_pool_connections=10,
        proxies={},
    )

    kwargs = {"region_name": AWS_REGION, "config": cfg}
    if AWS_ACCESS_KEY and AWS_SECRET_KEY:
        kwargs["aws_access_key_id"] = AWS_ACCESS_KEY
        kwargs["aws_secret_access_key"] = AWS_SECRET_KEY

    return boto3.client("s3", **kwargs), ""


def _versioned_key(key: str) -> str:
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    folder = os.path.dirname(key).replace("\\", "/")
    name = os.path.basename(key)
    stem, ext = os.path.splitext(name)
    return f"{folder}/historique/{stem}_{ts}{ext}" if folder else f"historique/{stem}_{ts}{ext}"


def _upload_one(s3, local_path: str, bucket: str, key: str, *, retries: int, backoff_base_s: float) -> UploadResult:
    if not os.path.exists(local_path):
        return UploadResult(key=key, status="ABSENT", message=f"Local introuvable: {local_path}")

    size = os.path.getsize(local_path)
    last_err = ""
    for attempt in range(1, retries + 1):
        try:
            t0 = time.time()
            s3.upload_file(local_path, bucket, key)
            dt = time.time() - t0
            mbs = (size / 1024 / 1024) / max(dt, 0.001)
            return UploadResult(key=key, status="OK", size_bytes=size, duration_s=dt, mbs=mbs)
        except Exception as e:
            last_err = f"{type(e).__name__}: {e}"
            if attempt < retries:
                sleep_s = backoff_base_s * (2 ** (attempt - 1))
                logger.warning("Retry %s/%s pour %s (attente %.1fs): %s", attempt, retries, key, sleep_s, last_err)
                time.sleep(sleep_s)
            else:
                return UploadResult(key=key, status="ECHEC", message=last_err, size_bytes=size)


def uploader_vers_s3(
    *,
    out_dir: str | os.PathLike[str] | None = None,
    prefix: str = "processed/",
    include_logs_clean: bool = True,
    parallelism: int = 4,
    retries: int = 3,
    backoff_base_s: float = 1.0,
    avec_versioning: bool = True,
    extra_files: Iterable[tuple[str, str]] | None = None,
    connect_timeout_s: int = 5,
    read_timeout_s: int = 30,
) -> dict:
    s3, err = _build_s3_client(connect_timeout_s, read_timeout_s)
    if s3 is None:
        logger.warning("[S3] Upload ignoré: %s", err)
        return {"status": "SKIPPED", "reason": "boto3_missing", "details": []}

    if not BUCKET_NAME:
        logger.warning("[S3] Upload ignoré: bucket manquant (S3_BUCKET_NAME)")
        return {"status": "SKIPPED", "reason": "bucket_missing", "details": []}

    resolved_out_dir = _resolve_output_dir(out_dir)

    files = [
        (str(resolved_out_dir / "erreurs_par_heure.csv"), f"{prefix}erreurs_par_heure.csv"),
        (str(resolved_out_dir / "tentatives_par_ip.csv"), f"{prefix}tentatives_par_ip.csv"),
        (str(resolved_out_dir / "events_par_service.csv"), f"{prefix}events_par_service.csv"),
    ]
    if include_logs_clean:
        files.insert(0, (str(resolved_out_dir / "logs_clean.csv"), f"{prefix}logs_clean.csv"))
    else:
        logger.info("Upload S3: logs_clean.csv ignorÃ© pour Ã©viter un blocage de fin de pipeline")
    if extra_files:
        files.extend(list(extra_files))

    logger.info("Upload %s fichier(s) -> bucket=%s region=%s threads=%s", len(files), BUCKET_NAME, AWS_REGION, parallelism)

    t0 = time.time()
    results: list[UploadResult] = []

    with ThreadPoolExecutor(max_workers=max(1, int(parallelism))) as ex:
        futures = {
            ex.submit(_upload_one, s3, local_path, BUCKET_NAME, key, retries=retries, backoff_base_s=backoff_base_s): (local_path, key)
            for local_path, key in files
        }

        for fut in as_completed(futures):
            _, key = futures[fut]
            res = fut.result()
            results.append(res)

            if res.status == "OK":
                logger.info("OK %s | %.1f Ko | %.2fs | %.2f Mo/s", res.key, (res.size_bytes or 0) / 1024, res.duration_s or 0, res.mbs or 0)
                if avec_versioning:
                    vkey = _versioned_key(res.key)
                    try:
                        s3.copy_object(
                            Bucket=BUCKET_NAME,
                            CopySource={"Bucket": BUCKET_NAME, "Key": res.key},
                            Key=vkey,
                        )
                        logger.info("Version %s", vkey)
                    except Exception as e:
                        logger.warning("Versioning échoué %s: %s", res.key, f"{type(e).__name__}: {e}")
            else:
                logger.warning("%s %s | %s", res.status, res.key, res.message)

    total_s = time.time() - t0
    nb_ok = sum(1 for r in results if r.status == "OK")

    report = {
        "timestamp": datetime.now().isoformat(),
        "bucket": BUCKET_NAME,
        "region": AWS_REGION,
        "nb_files": len(results),
        "nb_ok": nb_ok,
        "nb_fail": len(results) - nb_ok,
        "duration_s": round(total_s, 2),
        "details": [r.__dict__ for r in results],
    }

    os.makedirs(resolved_out_dir, exist_ok=True)
    report_path = resolved_out_dir / "upload_report.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    logger.info("Terminé: %s/%s OK | %.2fs | rapport=%s", nb_ok, len(results), total_s, report_path)
    return report
