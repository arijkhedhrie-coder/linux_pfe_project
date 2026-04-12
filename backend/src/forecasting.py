# forecasting.py — ARIMA (Statsmodels) — version finale intégrée

from __future__ import annotations

def prevoir_erreurs(erreurs_par_heure, steps: int = 6, min_points: int = 10) -> dict:
    """
    Prévoit les erreurs futures avec ARIMA.
    - Robuste: gère None / vide / peu de points
    - Compatible: accepte DataFrame avec colonne 'Nombre_Erreurs', Series, dict, list, ndarray
    - Non bloquant: si statsmodels indisponible => prévision ignorée
    Retour:
      {"message": str, "steps": int, "previsions": list[float]}
    """
    try:
        import pandas as pd
        import numpy as np
        from statsmodels.tsa.arima.model import ARIMA
    except Exception as e:
        print(f"[PREVISION] statsmodels indisponible, prévision ignorée: {type(e).__name__}: {e}")
        return {"message": "statsmodels indisponible", "steps": 0, "previsions": []}

    try:
        if erreurs_par_heure is None:
            print("[PREVISION] Aucune donnée — prévision ignorée")
            return {"message": "Pas de données", "steps": 0, "previsions": []}

        # DataFrame attendu côté toi
        if hasattr(erreurs_par_heure, "__getitem__") and not isinstance(erreurs_par_heure, (dict, list, tuple)):
            # ex: pandas.DataFrame
            if "Nombre_Erreurs" in getattr(erreurs_par_heure, "columns", []):
                serie = erreurs_par_heure["Nombre_Erreurs"]
            else:
                # ex: pandas.Series déjà
                serie = erreurs_par_heure
        else:
            serie = erreurs_par_heure

        # Normaliser en Series
        if isinstance(serie, dict):
            if len(serie) == 0:
                print("[PREVISION] Dictionnaire vide — prévision ignorée")
                return {"message": "Pas de données", "steps": 0, "previsions": []}
            serie = pd.Series(serie)
        elif isinstance(serie, (list, tuple, np.ndarray)):
            if len(serie) == 0:
                print("[PREVISION] Liste/array vide — prévision ignorée")
                return {"message": "Pas de données", "steps": 0, "previsions": []}
            serie = pd.Series(serie)
        elif isinstance(serie, pd.Series):
            pass
        else:
            # dernier recours: tenter conversion
            serie = pd.Series(serie)

        # Nettoyage: numeric + drop NaN
        serie = pd.to_numeric(serie, errors="coerce").dropna()

        if len(serie) == 0:
            print("[PREVISION] Série vide après nettoyage — prévision ignorée")
            return {"message": "Pas de données", "steps": 0, "previsions": []}

        if len(serie) < min_points:
            print(f"[PREVISION] Seulement {len(serie)} points — ARIMA nécessite ≥{min_points}")
            # On renvoie les valeurs existantes comme fallback
            return {
                "message": "Données insuffisantes",
                "steps": 0,
                "previsions": [float(x) for x in serie.values.tolist()],
            }

        # Fit + forecast
        modele = ARIMA(serie, order=(1, 1, 1))
        resultat = modele.fit()
        previsions = resultat.forecast(steps=int(steps))

        preds = [float(x) for x in previsions.tolist()]
        print(f"[PREVISION] {len(preds)} prévisions générées (steps={steps})")
        return {"message": "Succès", "steps": int(steps), "previsions": preds}

    except Exception as e:
        print(f"[PREVISION] Erreur ARIMA: {type(e).__name__}: {str(e)[:120]}")
        return {"message": f"Erreur: {type(e).__name__}", "steps": 0, "previsions": []}