# src/hybrid_detection.py
"""
HYBRID DETECTION ENGINE — Version 2026
Combine :
- Tes 5 couches générales (anomaly_detection.py)
- Les 10 couches SSH spécialisées (ml_engine.py)
"""

import pandas as pd
import numpy as np
from datetime import datetime

from src.anomaly_detection import detecter_anomalies, _charger_seuils_adaptatifs
from src.ml_engine import run_idps   # ← Import du fichier de ton binôme


def detecter_anomalies_hybride(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame, list[dict]]:
    """
    Détection hybride : généraliste + SSH ultra-spécialisée
    Retourne (df_annote, df_anomalies, alarmes)
    """
    print("\n" + "="*65)
    print(" DÉTECTION HYBRIDE 5+10 COUCHES (GÉNÉRAL + SSH)")
    print("="*65)

    # ── 1. Détection générale (tes 5 couches) ─────────────────────
    print("[HYBRID] → Lancement des 5 couches générales...")
    df_general, anomalies_general, alarmes_general = detecter_anomalies(df)

    # ── 2. Détection SSH spécialisée (10 couches de ton binôme) ─────
    print("[HYBRID] → Lancement des 10 couches SSH spécialisées...")
    try:
        df_ssh = run_idps(df)          # ← utilise directement la fonction de ml_engine.py
        ssh_anomalies = df_ssh[df_ssh['risk_level'].isin(['HIGH', 'MEDIUM'])] if not df_ssh.empty else pd.DataFrame()
    except Exception as e:
        print(f"[HYBRID] ⚠️ Erreur dans ml_engine : {e}")
        df_ssh = pd.DataFrame()
        ssh_anomalies = pd.DataFrame()

    # ── 3. Fusion intelligente des deux détections ────────────────
    df_final = df_general.copy()

    if not df_ssh.empty and 'source_ip' in df_ssh.columns:
        # Mapping des scores SSH vers tes IPs
        ssh_map = df_ssh.set_index('source_ip')['weighted_risk_score'].to_dict()
        ssh_level = df_ssh.set_index('source_ip')['risk_level'].to_dict()
        ssh_action = df_ssh.set_index('source_ip')['action'].to_dict()

        df_final['ssh_risk_score'] = df_final['IP_Source'].map(ssh_map).fillna(0)
        df_final['ssh_risk_level'] = df_final['IP_Source'].map(ssh_level).fillna('LOW')
        df_final['ssh_action'] = df_final['IP_Source'].map(ssh_action).fillna('MONITOR')

        # Boost du score final si détection SSH forte
        boost = np.where(
            df_final['ssh_risk_level'] == 'HIGH', 0.35,
            np.where(df_final['ssh_risk_level'] == 'MEDIUM', 0.20, 0.0)
        )
        df_final['score_final'] = np.clip(df_final['score_final'] + boost, 0, 1)

    # Mise à jour du niveau d'alerte
    df_final['niveau_alerte'] = df_final['score_final'].apply(
        lambda s: "CRITIQUE" if s >= 0.7 else "ANOMALIE" if s >= 0.5 else "SUSPECT" if s >= 0.3 else "NORMAL"
    )

    # ── 4. Alarmes hybrides ───────────────────────────────────────
    alarmes_hybrides = alarmes_general.copy()

    # Ajouter les alertes SSH HIGH
    for _, row in ssh_anomalies[ssh_anomalies['risk_level'] == 'HIGH'].iterrows():
        alarmes_hybrides.append({
            "timestamp": datetime.now().isoformat(),
            "ip": row['source_ip'],
            "niveau": "CRITIQUE",
            "score_final": float(row['weighted_risk_score'] / 100),
            "explication": f"SSH 10-couches HIGH RISK (score={row['weighted_risk_score']}) | {row.get('ip_reputation_label', '')}",
            "severite": "CRITIQUE",
            "message": f"🔴 CRITIQUE SSH | IP={row['source_ip']} | Score={row['weighted_risk_score']:.1f} | Action={row['action']}",
            "type": "DÉTECTION SSH 10-COUCHES",
            "valeur": int(row['total_failures']),
        })

    # Tri et déduplication
    alarmes_hybrides = sorted(alarmes_hybrides, key=lambda x: x.get('score_final', 0), reverse=True)

    print(f"[HYBRID] ✅ Détection terminée | Anomalies générales: {len(anomalies_general)} | SSH HIGH: {len(ssh_anomalies[ssh_anomalies['risk_level']=='HIGH'])}")

    return df_final, anomalies_general, alarmes_hybrides


# Fonction bonus : réentraînement hybride
def reentrainer_hybride(df: pd.DataFrame):
    """Réentraîne les deux moteurs"""
    from src.anomaly_detection import reentralner_avec_nouveaux_logs
    print("[HYBRID] Réentraînement du moteur général...")
    reentralner_avec_nouveaux_logs(df)
    # ml_engine n'a pas encore de réentraînement continu → on peut l'ajouter plus tard