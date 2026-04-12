import os
from pathlib import Path

import pandas as pd

from config.config import CHEMIN_RAW


def _discover_dataset_files(raw_dir: Path) -> list[Path]:
    csv_files = sorted(raw_dir.glob("*.csv"))
    return [p for p in csv_files if not p.name.endswith("_templates.csv")]


def _guess_raw_log_path(raw_dir: Path, stem: str) -> Path | None:
    """
    Supporte 2 conventions :
    - ta version : raw_dir/<stem>            (sans extension)
    - version binôme : raw_dir/<stem.replace('_structured','')> (souvent .log)
    """
    # 1) convention "sans extension"
    p1 = raw_dir / stem
    if p1.exists():
        return p1

    # 2) convention classique Drain/LogPai : Linux_2k.log_structured.csv -> Linux_2k.log
    base = stem.replace("_structured", "")
    for cand in (raw_dir / base, raw_dir / f"{base}.log", raw_dir / f"{base}.txt"):
        if cand.exists():
            return cand

    return None


def charger_donnees():
    raw_dir = Path(CHEMIN_RAW)
    dataset_files = _discover_dataset_files(raw_dir)

    if not dataset_files:
        raise FileNotFoundError(f"Aucun fichier CSV exploitable trouve dans {raw_dir}")

    structured_frames: list[pd.DataFrame] = []
    raw_frames: list[pd.DataFrame] = []
    template_frames: list[pd.DataFrame] = []

    for dataset_path in dataset_files:
        base_name = dataset_path.name

        df_structured = pd.read_csv(dataset_path, on_bad_lines="skip")
        df_structured["DatasetSource"] = base_name
        structured_frames.append(df_structured)

        # raw logs associés (si présents)
        raw_log_path = _guess_raw_log_path(raw_dir, dataset_path.stem)
        if raw_log_path and raw_log_path.exists():
            with open(raw_log_path, "r", encoding="utf-8", errors="ignore") as f:
                lignes_brutes = f.readlines()
            df_raw = pd.DataFrame(lignes_brutes, columns=["RawLog"])
            df_raw["DatasetSource"] = base_name
            raw_frames.append(df_raw)

        # templates associés (si présents)
        template_path = raw_dir / f"{dataset_path.stem}_templates.csv"
        if template_path.exists():
            df_template = pd.read_csv(template_path)
            df_template["DatasetSource"] = base_name
            template_frames.append(df_template)

    df = pd.concat(structured_frames, ignore_index=True)
    df_brut = (
        pd.concat(raw_frames, ignore_index=True)
        if raw_frames
        else pd.DataFrame(columns=["RawLog", "DatasetSource"])
    )
    df_templates = (
        pd.concat(template_frames, ignore_index=True)
        if template_frames
        else pd.DataFrame(columns=["DatasetSource"])
    )

    print(f"Fichiers charges : {len(df)} lignes depuis {len(dataset_files)} dataset(s)")
    return df, df_brut, df_templates