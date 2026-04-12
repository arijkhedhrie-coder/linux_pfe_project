# Configuration generale du projet
# Intégration : version binôme (AWS/S3/paths) + version principale (Anthropic API)

import os
from dotenv import load_dotenv

load_dotenv()

_BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# --- API Keys ---
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")

# --- AWS / S3 ---
AWS_REGION            = os.getenv("AWS_REGION", "us-east-1")
BUCKET_NAME           = os.getenv("S3_BUCKET_NAME", "pfe-linux-logs-supervision")
AWS_ACCESS_KEY_ID     = os.getenv("AWS_ACCESS_KEY_ID", "")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY", "")

# Aliases backward-compatible (si l'ancien code utilise ces noms courts)
AWS_ACCESS_KEY = AWS_ACCESS_KEY_ID
AWS_SECRET_KEY = AWS_SECRET_ACCESS_KEY

# --- Data paths ---
_default_raw = os.path.join(_BASE_DIR, "data", "raw")

# CHEMIN_RAW : priorité à la variable d'env, sinon chemin relatif au projet
# Pour Windows, définir CHEMIN_RAW dans le .env plutôt qu'un path hardcodé
CHEMIN_RAW = os.getenv("CHEMIN_RAW", _default_raw)

# --- App settings ---
SERVEUR_NOM = os.getenv("SERVEUR_NOM", "server1")
ANNEE       = os.getenv("ANNEE", "2026")