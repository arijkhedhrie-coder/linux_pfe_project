import os

# Dossier racine du projet
racine = r"C:\Users\LENOVO\pfe-linux-supervision"

# Liste de tous les dossiers a creer
dossiers = [
    "config",
    "data/raw",
    "data/processed",
    "src",
    "output",
    "notebooks",
]

# Creation des dossiers
for dossier in dossiers:
    os.makedirs(os.path.join(racine, dossier), exist_ok=True)
    print(f"Dossier cree : {dossier}")

# Liste des fichiers a creer avec leur contenu initial
fichiers = {
    "config/config.py": '''# Configuration generale du projet

BUCKET_NAME    = "pfe-linux-logs-supervision"
AWS_REGION     = "us-east-1"
AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")

CHEMIN_RAW  = r"C:\\Users\\LENOVO\\pfe-linux-supervision\\data\\raw"
SERVEUR_NOM = "server1"
ANNEE       = "2026"
''',

    "src/ingestion.py": '''import pandas as pd
import os
import sys
sys.path.append(r"C:\\Users\\LENOVO\\pfe-linux-supervision")
from config.config import CHEMIN_RAW

def charger_donnees():
    df = pd.read_csv(os.path.join(CHEMIN_RAW, "Linux_2k.log_structured.csv"))

    with open(os.path.join(CHEMIN_RAW, "Linux_2k.log"), "r", encoding="utf-8", errors="ignore") as f:
        lignes_brutes = f.readlines()
    df_brut = pd.DataFrame(lignes_brutes, columns=["RawLog"])

    df_templates = pd.read_csv(os.path.join(CHEMIN_RAW, "Linux_2k.log_templates.csv"))

    print(f"Fichiers charges : {len(df)} lignes")
    return df, df_brut, df_templates
''',

    "src/transformation.py": '''import pandas as pd
import re
import sys
sys.path.append(r"C:\\Users\\LENOVO\\pfe-linux-supervision")
from config.config import SERVEUR_NOM, ANNEE

def creer_datetime(df):
    df["DateTime"] = df["Month"] + " " + df["Date"].astype(str) + " " + ANNEE + " " + df["Time"]
    df["DateTime"] = pd.to_datetime(df["DateTime"], format="mixed", errors="coerce")
    return df

def detecter_etat(message):
    message = str(message).lower()
    if any(mot in message for mot in [
        "failed", "error", "critical", "denied",
        "invalid", "refused", "killed", "failure",
        "authentication failure", "unknown"
    ]):
        return "Error"
    elif any(mot in message for mot in [
        "warning", "warn", "timeout", "retry"
    ]):
        return "Warning"
    return "Info"

def extraire_ip(message):
    ip = re.search(r"\\b(\\d{1,3}\\.){3}\\d{1,3}\\b", str(message))
    return ip.group(0) if ip else None

def transformer(df):
    df = creer_datetime(df)
    df_clean = pd.DataFrame()
    df_clean["Date"]      = df["DateTime"]
    df_clean["Serveur"]   = SERVEUR_NOM
    df_clean["Service"]   = df["Component"]
    df_clean["Message"]   = df["Content"]
    df_clean["EventId"]   = df["EventId"]
    df_clean["Etat"]      = df_clean["Message"].apply(detecter_etat)
    df_clean["IP_Source"] = df_clean["Message"].apply(extraire_ip)
    print("Transformation terminee")
    return df_clean
''',

    "src/metriques.py": '''def calculer_metriques(df_clean):
    df_clean["Heure"] = df_clean["Date"].dt.floor("h")

    erreurs_par_heure = df_clean[df_clean["Etat"] == "Error"].groupby("Heure").size().reset_index()
    erreurs_par_heure.columns = ["Heure", "Nombre_Erreurs"]

    tentatives_par_ip = df_clean[df_clean["IP_Source"].notna()].groupby("IP_Source").size().reset_index()
    tentatives_par_ip.columns = ["IP_Source", "Nombre_Tentatives"]
    tentatives_par_ip = tentatives_par_ip.sort_values("Nombre_Tentatives", ascending=False)

    events_par_service = df_clean.groupby("Service").size().reset_index()
    events_par_service.columns = ["Service", "Nombre_Events"]
    events_par_service = events_par_service.sort_values("Nombre_Events", ascending=False)

    print("Metriques calculees")
    return erreurs_par_heure, tentatives_par_ip, events_par_service
''',

    "src/anomaly_detection.py": '''# Module de detection d anomalies - a completer
# Modele : IsolationForest (Scikit-learn)

def detecter_anomalies(tentatives_par_ip):
    from sklearn.ensemble import IsolationForest
    modele = IsolationForest(contamination=0.05, random_state=42)
    tentatives_par_ip["Anomalie"] = modele.fit_predict(
        tentatives_par_ip[["Nombre_Tentatives"]]
    )
    # -1 = anomalie  |  1 = normal
    anomalies = tentatives_par_ip[tentatives_par_ip["Anomalie"] == -1]
    print(f"Anomalies detectees : {len(anomalies)} IPs suspectes")
    return tentatives_par_ip, anomalies
''',

    "src/forecasting.py": '''# Module de prevision - a completer
# Modele : ARIMA (Statsmodels)

def prevoir_erreurs(erreurs_par_heure, steps=6):
    from statsmodels.tsa.arima.model import ARIMA
    serie = erreurs_par_heure["Nombre_Erreurs"]
    modele = ARIMA(serie, order=(1, 1, 1))
    resultat = modele.fit()
    previsions = resultat.forecast(steps=steps)
    print(f"Prevision sur {steps} prochaines heures :")
    print(previsions)
    return previsions
''',

    "src/upload_s3.py": '''import boto3
import os
import sys
sys.path.append(r"C:\\Users\\LENOVO\\pfe-linux-supervision")
from config.config import BUCKET_NAME, AWS_REGION, AWS_ACCESS_KEY, AWS_SECRET_KEY

def sauvegarder_localement(df_clean, erreurs_par_heure, tentatives_par_ip, events_par_service):
    os.makedirs("output", exist_ok=True)
    df_clean.to_csv("output/logs_clean.csv", index=False)
    erreurs_par_heure.to_csv("output/erreurs_par_heure.csv", index=False)
    tentatives_par_ip.to_csv("output/tentatives_par_ip.csv", index=False)
    events_par_service.to_csv("output/events_par_service.csv", index=False)
    print("Fichiers sauvegardes localement")

def uploader_vers_s3():
    s3 = boto3.client(
        "s3",
        region_name           = AWS_REGION,
        aws_access_key_id     = AWS_ACCESS_KEY,
        aws_secret_access_key = AWS_SECRET_KEY
    )
    fichiers = [
        ("output/logs_clean.csv",         "processed/logs_clean.csv"),
        ("output/erreurs_par_heure.csv",  "processed/erreurs_par_heure.csv"),
        ("output/tentatives_par_ip.csv",  "processed/tentatives_par_ip.csv"),
        ("output/events_par_service.csv", "processed/events_par_service.csv"),
    ]
    print("Upload vers S3 en cours...")
    for fichier_local, chemin_s3 in fichiers:
        s3.upload_file(fichier_local, BUCKET_NAME, chemin_s3)
        print(f"Uploade : {chemin_s3}")
    print("Tous les fichiers sont sur S3")
''',

    "main.py": '''import sys
sys.path.append(r"C:\\Users\\LENOVO\\pfe-linux-supervision")

from src.ingestion        import charger_donnees
from src.transformation   import transformer
from src.metriques        import calculer_metriques
from src.anomaly_detection import detecter_anomalies
from src.forecasting      import prevoir_erreurs
from src.upload_s3        import sauvegarder_localement, uploader_vers_s3

print("=== PIPELINE SUPERVISION LINUX ===")

# Etape 1 : Charger
df, df_brut, df_templates = charger_donnees()

# Etape 2 : Transformer
df_clean = transformer(df)

# Etape 3 : Metriques
erreurs_par_heure, tentatives_par_ip, events_par_service = calculer_metriques(df_clean)

# Etape 4 : Detection anomalies
tentatives_par_ip, anomalies = detecter_anomalies(tentatives_par_ip)

# Etape 5 : Prevision
previsions = prevoir_erreurs(erreurs_par_heure)

# Etape 6 : Sauvegarde et upload
sauvegarder_localement(df_clean, erreurs_par_heure, tentatives_par_ip, events_par_service)
uploader_vers_s3()

print("=== PIPELINE TERMINE AVEC SUCCES ===")
''',

    "requirements.txt": '''pandas
boto3
scikit-learn
statsmodels
''',

    "README.md": '''# PFE - Supervision Linux sur AWS

Pipeline de traitement de logs Linux avec detection d anomalies et prevision.

## Structure
- config/     : configuration AWS et chemins
- src/        : modules Python (ingestion, transformation, metriques, ML)
- data/raw/   : fichiers logs originaux
- data/processed/ : resultats CSV
- output/     : fichiers temporaires avant upload S3

## Execution
1. Copier les fichiers logs dans data/raw/
2. Lancer : python main.py
'''
}

# Creation de tous les fichiers
for chemin_fichier, contenu in fichiers.items():
    chemin_complet = os.path.join(racine, chemin_fichier)
    with open(chemin_complet, "w", encoding="utf-8") as f:
        f.write(contenu)
    print(f"Fichier cree : {chemin_fichier}")

print("\nArchitecture creee avec succes !")
print(f"Ton projet est dans : {racine}")
print("\nEtapes suivantes :")
print("1. Copier tes fichiers logs dans : data/raw/")
print("2. Ouvrir main.py dans Thonny")
print("3. Executer main.py")
