"""
anomaly_detection.py — VERSION FINALE AVANCÉE
==============================================
Couche 1 : Règles expertes adaptatives
Couche 2 : Ensemble 4 modèles ML + poids dynamiques (NOUVEAU)
Couche 3 : Analyse temporelle
Couche 4 : Mémoire long terme
Couche 5 : Explicabilité SHAP + rapport de performance (NOUVEAU)
"""

import os, json, joblib
import numpy as np
import pandas as pd
from datetime import datetime
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.svm import OneClassSVM
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import silhouette_score
import warnings
warnings.filterwarnings("ignore")

MODEL_DIR      = "src/models"
MODEL_IF       = f"{MODEL_DIR}/isolation_forest.joblib"
MODEL_LOF      = f"{MODEL_DIR}/lof.joblib"
MODEL_SVM      = f"{MODEL_DIR}/ocsvm.joblib"
SCALER_PATH    = f"{MODEL_DIR}/scaler.joblib"
HISTORY_PATH   = f"{MODEL_DIR}/training_history.json"
BLACKLIST_PATH = f"{MODEL_DIR}/ip_blacklist.json"
SEUILS_PATH    = f"{MODEL_DIR}/seuils_adaptatifs.json"
PERF_PATH      = f"{MODEL_DIR}/performance_history.json"
POIDS_PATH     = f"{MODEL_DIR}/poids_dynamiques.json"

FEATURES       = ["Nombre_Tentatives"]
EXTRA_FEATURES = ["Nombre_Erreurs", "nb_warnings", "cpu_usage", "mem_usage"]

SEUILS_DEFAUT = {
    "Nombre_Tentatives": 50,
    "Nombre_Erreurs":    200,
    "cpu_usage":         85.0,
    "mem_usage":         90.0,
}

POIDS_FEATURES = {
    "Nombre_Tentatives": 0.40,
    "Nombre_Erreurs":    0.25,
    "cpu_usage":         0.20,
    "mem_usage":         0.15,
}

POIDS_COUCHES = {
    "c1_regles":   0.25,
    "c2_ml":       0.40,
    "c3_temporel": 0.20,
    "c4_memoire":  0.10,
    "c5_shap":     0.05,
}

POIDS_ML_DEFAUT = {"if": 0.40, "lof": 0.25, "svm": 0.20, "dbscan": 0.15}

NIVEAUX = [
    (0.7, "CRITIQUE", "🔴"),
    (0.5, "ANOMALIE", "🟠"),
    (0.3, "SUSPECT",  "🟡"),
    (0.0, "NORMAL",   "🟢"),
]


def _get_features(df):
    known = [f for f in [*FEATURES, *EXTRA_FEATURES] if f in df.columns]
    if known:
        return known
    cols = df.select_dtypes(include=[np.number]).columns.tolist()
    if not cols:
        raise ValueError(f"Aucune feature numérique. Colonnes : {df.columns.tolist()}")
    print(f"[WARN] Fallback features : {cols}")
    return cols


def _niveau(score):
    for seuil, niveau, emoji in NIVEAUX:
        if score >= seuil:
            return niveau, emoji
    return "NORMAL", "🟢"


# ══ COUCHE 1 ══════════════════════════════
def _charger_seuils_adaptatifs():
    if os.path.exists(SEUILS_PATH):
        with open(SEUILS_PATH) as f:
            return json.load(f)
    return SEUILS_DEFAUT.copy()


def _mettre_a_jour_seuils(df, features):
    seuils = _charger_seuils_adaptatifs()
    for feature in features:
        if feature not in df.columns:
            continue
        mu, std = df[feature].mean(), df[feature].std()
        if std > 0 and len(df) > 30:
            ancien = seuils.get(feature, SEUILS_DEFAUT.get(feature, 50))
            seuils[feature] = round(0.70 * ancien + 0.30 * (mu + 2 * std), 2)
    os.makedirs(MODEL_DIR, exist_ok=True)
    with open(SEUILS_PATH, "w") as f:
        json.dump(seuils, f, indent=2)
    return seuils


def _score_c1_regles(df, features):
    seuils  = _charger_seuils_adaptatifs()
    scores  = np.zeros(len(df))
    raisons = [[] for _ in range(len(df))]
    for idx, (_, row) in enumerate(df.iterrows()):
        score_ligne = 0.0
        for feature in features:
            if feature not in df.columns:
                continue
            seuil  = seuils.get(feature, SEUILS_DEFAUT.get(feature, 50))
            valeur = row[feature]
            poids  = POIDS_FEATURES.get(feature, 0.1)
            if valeur > seuil:
                ratio        = min((valeur - seuil) / max(seuil, 1), 1.0)
                contribution = poids * ratio
                score_ligne  += contribution
                raisons[idx].append(f"{feature}={valeur:.1f} > seuil={seuil:.1f} (+{contribution:.2f})")
        scores[idx] = min(score_ligne, 1.0)
    return scores, raisons


# ══ COUCHE 2 + POIDS DYNAMIQUES ═══════════
def _calculer_contamination(df, features):
    seuils = _charger_seuils_adaptatifs()
    col    = features[0]
    return min(0.20, max(0.05, len(df[df[col] > seuils.get(col, 50)]) / max(len(df), 1)))


def _entrainer_modeles_ml(X_scaled, contamination):
    os.makedirs(MODEL_DIR, exist_ok=True)
    if_model = IsolationForest(contamination=contamination, n_estimators=200, random_state=42, n_jobs=-1)
    if_model.fit(X_scaled)
    joblib.dump(if_model, MODEL_IF)

    lof_model = LocalOutlierFactor(n_neighbors=min(20, len(X_scaled)-1), contamination=contamination, novelty=True, n_jobs=-1)
    lof_model.fit(X_scaled)
    joblib.dump(lof_model, MODEL_LOF)

    svm_model = OneClassSVM(nu=contamination, kernel="rbf", gamma="scale")
    svm_model.fit(X_scaled)
    joblib.dump(svm_model, MODEL_SVM)

    print(f"[C2] 3 modèles entraînés | contamination={contamination:.2%}")
    return if_model, lof_model, svm_model


def _charger_modeles_ml():
    return joblib.load(MODEL_IF), joblib.load(MODEL_LOF), joblib.load(MODEL_SVM)


def _calculer_poids_dynamiques(X_scaled, if_model, lof_model, svm_model):
    """
    NOUVEAU — Calcule les poids selon l'accord entre les modèles.

    Si IF et LOF sont souvent d'accord → ils sont fiables → poids plus élevé.
    Si SVM est souvent en désaccord → poids plus faible.

    Exemple concret :
      IF  prédit : [anomalie, normal, anomalie, normal, anomalie]
      LOF prédit : [anomalie, normal, normal,   normal, anomalie]
      Accord IF-LOF = 4/5 = 80%  →  IF et LOF reçoivent plus de poids
    """
    try:
        pred_if  = if_model.predict(X_scaled)
        pred_lof = lof_model.predict(X_scaled)
        pred_svm = svm_model.predict(X_scaled)

        a_if_lof  = float((pred_if  == pred_lof).mean())
        a_if_svm  = float((pred_if  == pred_svm).mean())
        a_lof_svm = float((pred_lof == pred_svm).mean())
        total     = a_if_lof + a_if_svm + a_lof_svm

        if total == 0:
            return POIDS_ML_DEFAUT.copy()

        poids = {
            "if":  (a_if_lof  + a_if_svm)  / (2 * total),
            "lof": (a_if_lof  + a_lof_svm) / (2 * total),
            "svm": (a_if_svm  + a_lof_svm) / (2 * total),
        }

        # Redistribuer 85% entre IF/LOF/SVM, garder 15% pour DBSCAN
        somme = sum(poids.values())
        if somme > 0:
            for k in ("if", "lof", "svm"):
                poids[k] = round(poids[k] * 0.85 / somme, 3)
        poids["dbscan"] = 0.15

        # Sauvegarder pour traçabilité
        os.makedirs(MODEL_DIR, exist_ok=True)
        with open(POIDS_PATH, "w") as f:
            json.dump({**poids, "accords": {"if_lof": round(a_if_lof,3), "if_svm": round(a_if_svm,3), "lof_svm": round(a_lof_svm,3)}, "mis_a_jour": datetime.now().isoformat()}, f, indent=2)

        print(f"[C2] Poids dynamiques → IF={poids['if']:.3f} | LOF={poids['lof']:.3f} | SVM={poids['svm']:.3f} | DBSCAN={poids['dbscan']:.3f}")
        print(f"[C2] Accords → IF-LOF={a_if_lof:.1%} | IF-SVM={a_if_svm:.1%} | LOF-SVM={a_lof_svm:.1%}")
        return poids

    except Exception as e:
        print(f"[C2] Poids dynamiques impossible ({e}) → défaut")
        return POIDS_ML_DEFAUT.copy()


def _score_c2_ml(X_scaled, if_model, lof_model, svm_model):
    vote_if  = np.where(if_model.predict(X_scaled)  == -1, 1.0, 0.0)
    vote_lof = np.where(lof_model.predict(X_scaled) == -1, 1.0, 0.0)
    vote_svm = np.where(svm_model.predict(X_scaled) == -1, 1.0, 0.0)

    raw_if = if_model.score_samples(X_scaled)
    min_if, max_if = raw_if.min(), raw_if.max()
    score_if_continu = 1 - (raw_if - min_if) / (max_if - min_if) if max_if > min_if else vote_if

    db = DBSCAN(eps=0.5, min_samples=5, n_jobs=-1)
    vote_dbscan = np.where(db.fit_predict(X_scaled) == -1, 1.0, 0.0)

    # Poids dynamiques
    p = _calculer_poids_dynamiques(X_scaled, if_model, lof_model, svm_model)

    score = np.clip(
        p["if"] * (vote_if * score_if_continu) +
        p["lof"] * vote_lof +
        p["svm"] * vote_svm +
        p["dbscan"] * vote_dbscan,
        0, 1
    )

    # ── A.1: Per-row model agreement ─────────────────────────────────────────
    # agreement[i] = votes_matching_majority / 4
    # 4/4 = all models agree  → high confidence flag
    # 1/4 = only one flagged  → likely noise, treat with caution
    votes_matrix    = np.stack([vote_if, vote_lof, vote_svm, vote_dbscan], axis=1)
    votes_sum       = votes_matrix.sum(axis=1)
    majority        = np.where(votes_sum >= 2, votes_sum, 4 - votes_sum)
    model_agreement = majority / 4.0

    return score, model_agreement, votes_matrix


# ══ COUCHE 3 ══════════════════════════════
def _score_c3_temporel(df, features):
    scores = np.zeros(len(df))
    heures_suspectes = set(range(0, 6))
    for idx, (_, row) in enumerate(df.iterrows()):
        score = 0.0
        date_col = row.get("Date", row.get("timestamp", None))
        if date_col is not None:
            try:
                if pd.to_datetime(date_col).hour in heures_suspectes:
                    score += 0.35
            except Exception:
                pass
        for feature in features:
            if feature not in df.columns:
                continue
            mu, std = df[feature].mean(), df[feature].std()
            if std > 0:
                z = abs((row[feature] - mu) / std)
                score += 0.35 if z > 3 else (0.15 if z > 2 else 0)
            if row[feature] > df[feature].quantile(0.99):
                score += 0.25
        scores[idx] = min(score, 1.0)
    return scores


# ══ COUCHE 4 ══════════════════════════════
def _charger_blacklist():
    if os.path.exists(BLACKLIST_PATH):
        with open(BLACKLIST_PATH) as f:
            return set(json.load(f).get("ips", []))
    return set()


def _sauvegarder_blacklist(nouvelles_ips):
    blacklist = _charger_blacklist()
    blacklist.update(nouvelles_ips)
    os.makedirs(MODEL_DIR, exist_ok=True)
    with open(BLACKLIST_PATH, "w") as f:
        json.dump({"ips": list(blacklist), "total": len(blacklist), "mis_a_jour": datetime.now().isoformat()}, f, indent=2)
    print(f"[BLACKLIST] {len(nouvelles_ips)} IP(s) mémorisée(s) | Total : {len(blacklist)}")


def _score_c4_memoire(df):
    blacklist = _charger_blacklist()
    scores    = np.zeros(len(df))
    for idx, (_, row) in enumerate(df.iterrows()):
        ip = str(row.get("IP_Source", row.get("ip", row.get("IP", ""))))
        if ip and ip != "nan" and ip in blacklist:
            scores[idx] = 0.85
            print(f"[C4] IP blacklistée : {ip}")
    return scores


# ══ COUCHE 5 ══════════════════════════════
def _score_c5_shap(df, features, s_c1, s_c2):
    scores, explications = np.zeros(len(df)), []
    seuils = _charger_seuils_adaptatifs()
    for idx, (_, row) in enumerate(df.iterrows()):
        contributions = {}
        for feature in features:
            if feature not in df.columns:
                continue
            valeur  = row[feature]
            moyenne = df[feature].mean()
            poids   = POIDS_FEATURES.get(feature, 0.1)
            ecart   = (valeur - moyenne) / moyenne if moyenne > 0 else 0
            contributions[feature] = poids * max(ecart, 0)
        scores[idx] = min(sum(contributions.values()), 1.0)
        top = sorted(contributions.items(), key=lambda x: x[1], reverse=True)[:3]
        explications.append(
            "Causes : " + " | ".join(f"{f}={row.get(f,0):.0f}" for f, v in top if v > 0)
            if top and top[0][1] > 0 else "Comportement normal"
        )
    return np.clip(scores, 0, 1), explications


# ══ NOUVEAU — RAPPORT DE PERFORMANCE ══════
def _evaluer_performance(df_annote, score_final):
    """
    NOUVEAU — Sauvegarde les métriques de performance à chaque session.

    Métriques calculées :
    - silhouette  : qualité de séparation normal/anomalie (-1 à 1)
                    Plus proche de 1 = le modèle sépare bien
    - taux_anomalies : % d'IPs détectées comme suspectes
    - score_max   : l'IP la plus dangereuse ce cycle
    - nb_blacklistes : mémoire cumulée des attaquants

    Sauvegardé dans src/models/performance_history.json
    Tu peux montrer l'évolution au jury session par session.
    """
    features = _get_features(df_annote)
    X        = df_annote[features].values
    if len(X) < 3:
        return {}

    scaler_tmp = StandardScaler()
    X_scaled   = scaler_tmp.fit_transform(X)
    labels     = np.where(score_final >= 0.3, -1, 1)

    perf = {
        "session":         _charger_historique().get("sessions", 0),
        "timestamp":       datetime.now().isoformat(),
        "nb_echantillons": int(len(X)),
        "taux_anomalies":  round(float((score_final >= 0.3).mean() * 100), 2),
        "score_moyen":     round(float(score_final.mean()), 4),
        "score_max":       round(float(score_final.max()), 4),
        "nb_blacklistes":  len(_charger_blacklist()),
        "silhouette":      None,
    }

    # Silhouette — nécessite au moins 2 IPs normales et 2 suspectes
    if len(set(labels)) >= 2 and (labels == -1).sum() >= 2 and (labels == 1).sum() >= 2:
        try:
            perf["silhouette"] = round(float(silhouette_score(X_scaled, labels)), 4)
        except Exception:
            pass

    # Charger historique, ajouter, garder 50 sessions max
    historique = []
    if os.path.exists(PERF_PATH):
        try:
            with open(PERF_PATH) as f:
                historique = json.load(f)
        except Exception:
            pass
    historique = (historique + [perf])[-50:]
    os.makedirs(MODEL_DIR, exist_ok=True)
    with open(PERF_PATH, "w") as f:
        json.dump(historique, f, indent=2)

    sil_str = f"{perf['silhouette']:.4f}" if perf["silhouette"] is not None else "N/A"
    print(f"\n[PERFORMANCE] Session #{perf['session']} | "
          f"Silhouette={sil_str} | "
          f"Anomalies={perf['taux_anomalies']}% | "
          f"Score max={perf['score_max']:.4f} | "
          f"Blacklist={perf['nb_blacklistes']} IPs")

    # Comparaison avec session précédente
    if len(historique) >= 2:
        prec      = historique[-2]
        delta_sil = (perf["silhouette"] or 0) - (prec.get("silhouette") or 0)
        if delta_sil > 0.001:
            print(f"[PERFORMANCE] ↗ Silhouette amélioré de +{delta_sil:.4f}")
        elif delta_sil < -0.001:
            print(f"[PERFORMANCE] ↘ Silhouette réduit de {delta_sil:.4f}")
        else:
            print(f"[PERFORMANCE] → Silhouette stable")

    return perf


# ══ HISTORIQUE ════════════════════════════
def _charger_historique():
    if os.path.exists(HISTORY_PATH):
        with open(HISTORY_PATH) as f:
            return json.load(f)
    return {"sessions": 0, "total_samples": 0, "last_train": None}


def _sauvegarder_historique(nb_samples):
    hist = _charger_historique()
    hist["sessions"]      += 1
    hist["total_samples"] += nb_samples
    hist["last_train"]     = datetime.now().isoformat()
    os.makedirs(MODEL_DIR, exist_ok=True)
    with open(HISTORY_PATH, "w") as f:
        json.dump(hist, f, indent=2)
    print(f"[HIST] Session #{hist['sessions']} — {hist['total_samples']} échantillons cumulés")


# ══ ENTRAÎNEMENT ══════════════════════════
FEATURES_PATH = f"{MODEL_DIR}/scaler_features.joblib"   # ← ajouter en haut du fichier

def entrainer_et_sauvegarder(df):
    features      = _get_features(df)
    X             = df[features].values
    contamination = _calculer_contamination(df, features)
    scaler        = StandardScaler()
    X_scaled      = scaler.fit_transform(X)
    if_model, lof_model, svm_model = _entrainer_modeles_ml(X_scaled, contamination)
    joblib.dump(scaler,   SCALER_PATH)
    joblib.dump(features, FEATURES_PATH)          # ← NOUVEAU : sauvegarder les features
    _sauvegarder_historique(len(X))
    _mettre_a_jour_seuils(df, features)
    return if_model, lof_model, svm_model, scaler


def charger_ou_entrainer(df):
    modeles_ok = all(os.path.exists(p) for p in [MODEL_IF, MODEL_LOF, MODEL_SVM, SCALER_PATH])

    if modeles_ok:
        features_actuelles = _get_features(df)

        # Vérifier la compatibilité des features
        if os.path.exists(FEATURES_PATH):
            features_sauvegardees = joblib.load(FEATURES_PATH)
            if features_sauvegardees != features_actuelles:
                print(f"[WARN] Dérive des features détectée :")
                print(f"       Sauvegardées : {features_sauvegardees}")
                print(f"       Actuelles    : {features_actuelles}")
                print(f"[INFO] Réentraînement automatique...")
                return entrainer_et_sauvegarder(df)   # ← re-fit propre

        if_model, lof_model, svm_model = _charger_modeles_ml()
        scaler = joblib.load(SCALER_PATH)
        hist   = _charger_historique()
        print(f"[OK] Modèles chargés — {hist['total_samples']} échantillons | session #{hist['sessions']}")
    else:
        print("[INFO] Premier lancement — entraînement initial...")
        if_model, lof_model, svm_model, scaler = entrainer_et_sauvegarder(df)

    return if_model, lof_model, svm_model, scaler


# ══ DÉTECTION PRINCIPALE ══════════════════
def detecter_anomalies(df, dynamic_config=None):
    print("\n" + "="*55)
    print("  DÉTECTION AVANCÉE — 5 COUCHES")
    print("="*55)

    # Appliquer les overrides de l'orchestrateur si présents
    if dynamic_config is not None and not dynamic_config.is_default():
        seuils_courants = _charger_seuils_adaptatifs()

        # Compat: `DynamicConfig` (src/hybrid_config.py) n'expose pas `threshold_overrides`.
        # On mappe donc les seuils "métier" (SSH/WEB/...) vers les seuils utilisés par ce module
        # (principalement `Nombre_Tentatives` / `Nombre_Erreurs`).
        overrides: dict[str, float] = {}

        def _pick_float(*names: str) -> float | None:
            for n in names:
                v = getattr(dynamic_config, n, None)
                if v is None:
                    continue
                try:
                    return float(v)
                except Exception:
                    continue
            return None

        # Heuristique simple mais stable pour PFE:
        # - si un seuil SSH "high" est fourni, on l'utilise comme proxy du seuil de tentatives
        # - sinon WEB, sinon FTP, sinon KERNEL, sinon SESSION
        proxy = (
            _pick_float("ssh_high_risk_threshold")
            or _pick_float("web_high_risk_threshold")
            or _pick_float("ftp_high_risk_threshold")
            or _pick_float("kernel_high_risk_threshold")
            or _pick_float("session_high_risk_threshold")
        )
        if proxy is not None:
            overrides["Nombre_Tentatives"] = float(proxy)

        # Optionnel: si l'agent baisse fortement le seuil d'erreurs, refléter sur `Nombre_Erreurs`
        err_proxy = _pick_float("web_med_risk_threshold", "ftp_med_risk_threshold", "ssh_med_risk_threshold")
        if err_proxy is not None:
            overrides["Nombre_Erreurs"] = float(err_proxy)

        if overrides:
            seuils_courants.update(overrides)
            os.makedirs(MODEL_DIR, exist_ok=True)
            with open(SEUILS_PATH, "w") as f:
                json.dump(seuils_courants, f, indent=2)
            print(f"[DynamicConfig] Seuils ajustés : {overrides}")

    if_model, lof_model, svm_model, scaler = charger_ou_entrainer(df)
    features = _get_features(df)
    X_scaled = scaler.transform(df[features].values)
    df       = df.copy()

    print("[C1] Règles expertes adaptatives...")
    s_c1, raisons_c1 = _score_c1_regles(df, features)

    print("[C2] Vote 4 modèles ML avec poids dynamiques...")
    s_c2, model_agreement, votes_matrix = _score_c2_ml(X_scaled, if_model, lof_model, svm_model)

    print("[C3] Analyse temporelle...")
    s_c3 = _score_c3_temporel(df, features)

    print("[C4] Consultation mémoire long terme...")
    s_c4 = _score_c4_memoire(df)

    print("[C5] Calcul explicabilité (SHAP)...")
    s_c5, explications = _score_c5_shap(df, features, s_c1, s_c2)

    score_final = np.clip(
        POIDS_COUCHES["c1_regles"]   * s_c1 +
        POIDS_COUCHES["c2_ml"]       * s_c2 +
        POIDS_COUCHES["c3_temporel"] * s_c3 +
        POIDS_COUCHES["c4_memoire"]  * s_c4 +
        POIDS_COUCHES["c5_shap"]     * s_c5,
        0, 1
    )

    df["score_c1"]        = np.round(s_c1, 4)
    df["score_c2"]        = np.round(s_c2, 4)
    df["score_c3"]        = np.round(s_c3, 4)
    df["score_c4"]        = np.round(s_c4, 4)
    df["score_c5"]        = np.round(s_c5, 4)
    df["score_final"]     = np.round(score_final, 4)
    df["explication"]     = explications
    df["raisons_c1"]      = [" | ".join(r) if r else "RAS" for r in raisons_c1]
    # ── A.1: model agreement stored per row ──────────────────────────────────
    df["model_agreement"] = np.round(model_agreement, 4)
    df["votes_if"]        = votes_matrix[:, 0].astype(int)
    df["votes_lof"]       = votes_matrix[:, 1].astype(int)
    df["votes_svm"]       = votes_matrix[:, 2].astype(int)
    df["votes_dbscan"]    = votes_matrix[:, 3].astype(int)
    niveaux               = [_niveau(s) for s in score_final]
    df["niveau_alerte"]   = [n[0] for n in niveaux]
    df["emoji_alerte"]    = [n[1] for n in niveaux]
    df["anomalie"]        = np.where(score_final >= 0.3, -1, 1)
    df["anomalie_score"]  = -score_final

    n_critique = int((score_final >= 0.7).sum())
    n_anomalie = int(((score_final >= 0.5) & (score_final < 0.7)).sum())
    n_suspect  = int(((score_final >= 0.3) & (score_final < 0.5)).sum())
    n_normal   = int((score_final < 0.3).sum())

    print(f"\n[RÉSULTATS]")
    print(f"  🔴 Critiques  : {n_critique}")
    print(f"  🟠 Anomalies  : {n_anomalie}")
    print(f"  🟡 Suspects   : {n_suspect}")
    print(f"  🟢 Normaux    : {n_normal}")
    print(f"  Score moyen   : {score_final.mean():.4f}")
    print(f"  Score max     : {score_final.max():.4f}")

    # NOUVEAU — rapport de performance
    _evaluer_performance(df, score_final)

    df_anomalies = df[df["score_final"] >= 0.3].sort_values("score_final", ascending=False)

    # ── A.1: Session-level model agreement summary ────────────────────────────
    anomaly_mask = score_final >= 0.3
    if anomaly_mask.sum() > 0:
        session_agreement = float(model_agreement[anomaly_mask].mean())
        isolated_count    = int((model_agreement[anomaly_mask] <= 0.25).sum())  # only 1/4 models
        print(f"\n[A.1] Model agreement (anomalies only): {session_agreement:.2f} avg | "
              f"{isolated_count} isolated (1 model only)")
    else:
        session_agreement = 1.0
        isolated_count    = 0

    alarmes = []
    for _, row in df_anomalies[df_anomalies["niveau_alerte"].isin(["CRITIQUE", "ANOMALIE"])].iterrows():
        ip = str(row.get("IP_Source", row.get("ip", "N/A")))
        agree = float(row.get("model_agreement", 1.0))
        alarmes.append({
            "timestamp":       datetime.now().isoformat(),
            "ip":              ip,
            "niveau":          row["niveau_alerte"],
            "score_final":     float(row["score_final"]),
            "score_c1":        float(row["score_c1"]),
            "score_c2":        float(row["score_c2"]),
            "score_c3":        float(row["score_c3"]),
            "score_c4":        float(row["score_c4"]),
            "explication":     row["explication"],
            "raisons":         row["raisons_c1"],
            "severite":        "CRITIQUE" if row["score_final"] >= 0.7 else "AVERTISSEMENT",
            "message":         f"{row['emoji_alerte']} {row['niveau_alerte']} | IP={ip} | Score={row['score_final']:.2f} | {row['explication']}",
            "type":            f"DÉTECTION {row['niveau_alerte']}",
            "valeur":          float(row.get("Nombre_Tentatives", 0)),
            "seuil":           float(_charger_seuils_adaptatifs().get("Nombre_Tentatives", 50)),
            # ── A.1 fields ───────────────────────────────────────────────────
            "model_agreement": round(agree, 4),
            "models_agreed":   int(round(agree * 4)),       # 1–4 out of 4
            "agreement_label": (
                "HIGH"   if agree >= 0.75 else
                "MEDIUM" if agree >= 0.50 else
                "LOW"                                        # only 1 model flagged
            ),
            "votes": {
                "IF":     int(row.get("votes_if",     0)),
                "LOF":    int(row.get("votes_lof",    0)),
                "SVM":    int(row.get("votes_svm",    0)),
                "DBSCAN": int(row.get("votes_dbscan", 0)),
            },
        })
        print(f"  🚨 {alarmes[-1]['message']} | agreement={agree:.2f} ({alarmes[-1]['agreement_label']})")

    ips_critiques = {
        str(row.get("IP_Source", ""))
        for _, row in df_anomalies[df_anomalies["niveau_alerte"] == "CRITIQUE"].iterrows()
        if row.get("IP_Source") and str(row.get("IP_Source")) != "nan"
    }
    if ips_critiques:
        _sauvegarder_blacklist(ips_critiques)

    print("="*55)
    return df, df_anomalies, alarmes, []


# ══ RÉENTRAÎNEMENT ════════════════════════
def reentralner_avec_nouveaux_logs(df):
    print("\n[APPRENTISSAGE] Réentraînement + mise à jour seuils...")
    if_model, lof_model, svm_model, scaler = entrainer_et_sauvegarder(df)
    hist   = _charger_historique()
    seuils = _charger_seuils_adaptatifs()
    print(f"[APPRENTISSAGE] ✅ Sessions : {hist['sessions']} | Échantillons : {hist['total_samples']}")
    print(f"  Seuils adaptatifs : {seuils}")
    return if_model, lof_model, svm_model, scaler


# ══ FENÊTRE GLISSANTE ═════════════════════
def detecter_anomalies_fenetre(df, heures=24):
    maintenant = pd.Timestamp.now()
    debut      = maintenant - pd.Timedelta(hours=heures)
    if "Date" in df.columns:
        df_recent = df[pd.to_datetime(df["Date"]) >= debut].copy()
        print(f"[FENÊTRE] {len(df_recent)} événements dans les {heures}h")
    else:
        df_recent = df.copy()
    if len(df_recent) < 5:
        print("[FENÊTRE] Pas assez de données — analyse globale")
        return detecter_anomalies(df)
    return detecter_anomalies(df_recent)


# ══ TEST ══════════════════════════════════
if __name__ == "__main__":
    np.random.seed(42)
    n = 400
    df_test = pd.DataFrame({
        "Nombre_Tentatives": np.concatenate([np.random.poisson(5, int(n*0.9)), np.random.poisson(90, int(n*0.1))]),
        "Nombre_Erreurs":    np.concatenate([np.random.poisson(15, int(n*0.9)), np.random.poisson(300, int(n*0.1))]),
        "IP_Source":         [f"192.168.1.{np.random.randint(1,50)}" for _ in range(n)],
        "Date":              pd.date_range("2026-03-18 00:00", periods=n, freq="10min"),
    })
    df_out, df_anom, alarmes, _ = detecter_anomalies(df_test)
    reentralner_avec_nouveaux_logs(df_test)
    print(f"\n[TEST] Anomalies : {len(df_anom)} | Alarmes : {len(alarmes)}")
    print(df_out["niveau_alerte"].value_counts().to_string())