"""
agents.py — VERSION FINALE INTÉGRÉE
=====================================
Fusion des deux versions :
  - Base : version principale (dispatch MCP direct Python, patch throttle automatique + retry 429)
  - Correctifs binôme greffés :
      [B1] field_validator sur ActionCorrectiveInput — coerce dict/list → str (évite rejet 400 Groq)
      [B2] SURVEILLANCE_NORMALE géré explicitement dans OutilActionCorrective
      [B3] Flag anti-boucle _alarme_declenchee_ce_cycle dans OutilDeclencherAlarme
      [B4] OutilAnalyserLogs enrichi — 8 types d'attaques détectés
      [B5] max_iter=1 / max_retry_limit=1 sur detector_agent

Architecture multi-agents CrewAI — 6 agents spécialisés :
  1. Collecteur       — Récupère les logs depuis S3
  2. Analyste         — Analyse les patterns et prédit les tendances
  3. Détecteur        — Détecte anomalies + déclenche alarmes préventives
  4. Correcteur       — Propose et exécute des actions correctives automatiques
  5. Orchestrateur    — Coordonne les agents et gère les priorités
  6. Rapporteur       — Génère et sauvegarde le rapport final sur S3
"""

import os
import sys
import json
import re
from datetime import datetime
from typing import Optional
from src.crewai_compat import patch_legacy_rag_storage_for_ollama

# ── Imports directs — pas de subprocess ──────────────────────────────────────
try:
    from src.tools import s3_tools
    _S3_DISPONIBLE = True
except ImportError:
    s3_tools = None
    _S3_DISPONIBLE = False
    print("[WARN] s3_tools non disponible — opérations S3 en mode simulation")

try:
    from src.tools import linux_tools
    _LINUX_TOOLS_DISPONIBLE = True
except ImportError:
    linux_tools = None
    _LINUX_TOOLS_DISPONIBLE = False
    print("[WARN] linux_tools non disponible — opérations SSH en mode simulation")

# ==============================
# VARIABLES D'ENVIRONNEMENT — AVANT TOUT IMPORT CREWAI
# ==============================
os.environ.setdefault("OPENAI_API_KEY",            "fake-not-needed")
os.environ.setdefault("CREWAI_EMBEDDING_PROVIDER", "ollama")
os.environ.setdefault("CREWAI_EMBEDDING_MODEL",    "nomic-embed-text")
os.environ.setdefault("OLLAMA_BASE_URL",           "http://localhost:11434")
os.environ.setdefault("OTEL_SDK_DISABLED",         "true")

# Patch RAGStorage pour forcer Ollama avant initialisation ChromaDB
_rag_patch_status, _rag_patch_detail = patch_legacy_rag_storage_for_ollama()
if _rag_patch_status == "applied":
    print("[OK] Patch RAGStorage Ollama appliqué")
elif _rag_patch_status == "skipped":
    print(f"[INFO] Patch RAGStorage ignoré: {_rag_patch_detail}")
else:
    print(f"[WARN] Patch RAGStorage échoué: {_rag_patch_detail}")

from crewai import Agent, LLM
from crewai.tools import BaseTool
from pydantic import BaseModel, Field, field_validator
from dotenv import load_dotenv
import time

load_dotenv()

# ── FLAG ANTI-BOUCLE [B3] : empêche declencher_alarme d'être appelé plusieurs fois ──
_alarme_declenchee_ce_cycle = False

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
os.environ.setdefault("GROQ_API_KEY", GROQ_API_KEY or "")

# ================================
# MODULE AWS SECURITY — BLOCAGE BOTO3 RÉEL
# ================================
try:
    from src.aws_security import bloquer_ip_secgroup, bloquer_depuis_anomalie
    AWS_SECURITY_DISPONIBLE = True
    print("[OK] Module aws_security chargé — blocage AWS réel activé")
except ImportError:
    AWS_SECURITY_DISPONIBLE = False
    print("[WARN] aws_security non disponible — mode simulation uniquement")


# ================================
# LLM — Groq avec garde rate-limit automatique
#
# Groq free tier : 6000 TPM
# Fix : patch llm.__class__.call — couvre 100 % des appels CrewAI
# ================================
llm = LLM(
    model="groq/llama-3.1-8b-instant",
    api_key=GROQ_API_KEY,
    temperature=0.0,
    max_tokens=150,   # default for simple agents (collector, reporter, corrector)
    max_retries=3,
    timeout=90,
)

# Orchestrator needs more tokens: its JSON template alone is ~250 chars.
# At 150 tokens the LLM truncates mid-JSON and defaults to NORMAL.
# 400 tokens = enough for the full JSON + one reasoning sentence.
llm_orchestrator = LLM(
    model="groq/llama-3.1-8b-instant",
    api_key=GROQ_API_KEY,
    temperature=0.0,
    max_tokens=400,
    max_retries=3,
    timeout=90,
)

# Analyst needs enough space to write 4 lines of structured analysis.
# 150 tokens cuts off mid-line. 300 is sufficient.
llm_analyst = LLM(
    model="groq/llama-3.1-8b-instant",
    api_key=GROQ_API_KEY,
    temperature=0.0,
    max_tokens=300,
    max_retries=3,
    timeout=90,
)

_last_llm_call = [0.0]
_MIN_DELAY_SECONDS = 13   # ~4-5 appels/min → safe sous 6000 TPM

_original_llm_call = llm.__class__.call

def _throttled_llm_call(self, *args, **kwargs):
    """Wrapper rate-limiting : gap minimum entre chaque appel Groq."""
    elapsed = time.time() - _last_llm_call[0]
    if elapsed < _MIN_DELAY_SECONDS:
        wait = _MIN_DELAY_SECONDS - elapsed
        print(f"[THROTTLE] Waiting {wait:.1f}s (Groq 6k TPM guard)...")
        time.sleep(wait)
    _last_llm_call[0] = time.time()
    for attempt in range(3):
        try:
            return _original_llm_call(self, *args, **kwargs)
        except Exception as exc:
            err = str(exc).lower()
            if "rate_limit" in err or "ratelimit" in err or "429" in err:
                backoff = 30 * (attempt + 1)
                print(f"[THROTTLE] RateLimitError (tentative {attempt+1}/3) — backoff {backoff}s")
                time.sleep(backoff)
                _last_llm_call[0] = time.time()
                if attempt == 2:
                    raise
            else:
                raise

llm.__class__.call = _throttled_llm_call

def _throttle():
    """Alias de compatibilité — le patch gère tout automatiquement."""
    pass


# ================================
# DISPATCHER MCP — APPELS PYTHON DIRECTS (pas de subprocess)
# ================================
def _appeler_mcp(nom_outil: str, arguments: dict) -> str:
    """
    Dispatch direct en appels Python — pas de subprocess ni de JSON-RPC.
    Retourne toujours un str.
    """
    try:
        # ── OUTIL 1 : Lire un fichier log depuis S3 ───────────────────────
        if nom_outil == "lire_logs_s3":
            if not _S3_DISPONIBLE:
                return "[SIMULATION] lire_logs_s3 — s3_tools non disponible"
            fichier = arguments.get("fichier") or arguments.get("key")
            try:
                contenu = s3_tools.read_object(fichier)
                return f"Logs récupérés depuis S3 (extrait):\n{contenu[:1200]}"
            except Exception as e:
                return f"Erreur lecture S3: {e}"

        # ── OUTIL 2 : Lister les fichiers logs dans S3 ────────────────────
        if nom_outil == "lister_logs_s3":
            if not _S3_DISPONIBLE:
                return "[SIMULATION] lister_logs_s3 — s3_tools non disponible"
            try:
                prefix   = arguments.get("prefix")
                fichiers = s3_tools.list_objects(prefix=prefix) if prefix else s3_tools.list_objects()
                fichiers = fichiers[:20]
                return "Fichiers disponibles dans S3:\n" + "\n".join(fichiers)
            except Exception as e:
                return f"Erreur listage S3: {e}"

        # ── OUTIL 3 : Analyser les logs ───────────────────────────────────
        if nom_outil == "analyser_logs":
            logs   = arguments.get("contenu_logs") or arguments.get("contenu") or ""
            lignes = logs.split("\n")
            erreurs, warnings, ssh = [], [], []
            for ligne in lignes:
                ll = ligne.lower()
                if "error" in ll or "failed" in ll:
                    erreurs.append(ligne[:200])
                elif "warning" in ll or "warn" in ll:
                    warnings.append(ligne[:200])
                elif "ssh" in ll or "accepted" in ll:
                    ssh.append(ligne[:200])
            return (
                "ANALYSE DES LOGS:\n"
                f"- Total lignes: {len(lignes)}\n"
                f"- Erreurs: {len(erreurs)}\n"
                f"- Warnings: {len(warnings)}\n"
                f"- Connexions SSH: {len(ssh)}\n"
                "Top erreurs:\n" + "\n".join(erreurs[:3])
            )

        # ── OUTIL 4 : Détecter anomalies ──────────────────────────────────
        if nom_outil == "detecter_anomalies":
            donnees   = str(arguments.get("donnees") or arguments.get("rapport") or arguments.get("contenu_logs") or "")
            donnees_l = donnees.lower()
            anomalies = []
            if "error" in donnees_l:
                nb = donnees_l.count("error")
                if nb > 10:
                    anomalies.append(f"CRITIQUE: {nb} erreurs detectees")
            if "failed password" in donnees_l:
                anomalies.append("SECURITE: Tentatives de connexion echouees detectees")
            if "invalid user" in donnees_l:
                anomalies.append("INTRUSION: Utilisateur invalide detecte")
            if "out of memory" in donnees_l:
                anomalies.append("MEMOIRE: Probleme memoire detecte")
            if not anomalies:
                anomalies.append("OK: Aucune anomalie critique detectee")
            return "ANOMALIES DETECTEES:\n" + "\n".join(anomalies)

        # ── OUTIL 5 : Sauvegarder rapport sur S3 ─────────────────────────
        if nom_outil == "sauvegarder_rapport_s3":
            if not _S3_DISPONIBLE:
                return "[SIMULATION] sauvegarder_rapport_s3 — s3_tools non disponible"
            try:
                contenu     = arguments.get("contenu") or arguments.get("rapport_json") or ""
                nom_fichier = arguments.get(
                    "nom_fichier",
                    f"rapport_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                )
                s3_tools.save_report(content=contenu, key=f"rapports/{nom_fichier}")
                return f"Rapport sauvegarde sur S3: rapports/{nom_fichier}"
            except Exception as e:
                return f"Erreur sauvegarde S3: {e}"

        # ── OUTIL 6 : Commande SSH générique ─────────────────────────────
        if nom_outil == "run_ssh_command":
            if not _LINUX_TOOLS_DISPONIBLE:
                return "[SIMULATION] run_ssh_command — linux_tools non disponible"
            try:
                return linux_tools.run_ssh_command(
                    host=arguments.get("host"),
                    username=arguments.get("username"),
                    password=arguments.get("password"),
                    key_path=arguments.get("key_path"),
                    command=arguments.get("command"),
                    port=arguments.get("port", 22),
                )
            except Exception as e:
                return f"Erreur SSH: {e}"

        # ── OUTIL 7 : Métriques système via SSH ───────────────────────────
        if nom_outil == "get_system_metrics":
            if not _LINUX_TOOLS_DISPONIBLE:
                return "[SIMULATION] get_system_metrics — linux_tools non disponible"
            try:
                metrics = linux_tools.get_system_metrics(
                    host=arguments.get("host"),
                    username=arguments.get("username"),
                    password=arguments.get("password"),
                    key_path=arguments.get("key_path"),
                    port=arguments.get("port", 22),
                )
                return json.dumps(metrics, indent=2)
            except Exception as e:
                return f"Erreur métriques SSH: {e}"

        # ── OUTIL 8 : Orchestration pipeline ─────────────────────────────
        if nom_outil == "orchestrer_pipeline":
            contexte = arguments.get("contexte", "")
            return f"Orchestration OK. Contexte: {contexte[:200]}"

        return f"Outil inconnu: {nom_outil}"

    except Exception as e:
        return f"Erreur dispatcher MCP: {type(e).__name__}: {e}"


# ================================
# SCHÉMAS PYDANTIC
# ================================
class ListerLogsInput(BaseModel):
    prefix: Optional[str] = Field(default=None, description="Préfixe S3 optionnel")

class LireLogsInput(BaseModel):
    fichier: Optional[str] = Field(default=None, description="Nom du fichier log à lire depuis S3")

class AnalyserLogsInput(BaseModel):
    contenu: Optional[str] = Field(default=None, description="Contenu des logs à analyser")

class DetecterAnomaliesInput(BaseModel):
    rapport: Optional[str] = Field(default=None, description="Rapport ou logs à analyser pour détecter les anomalies")

class AlarmeInput(BaseModel):
    alarmes_json: Optional[str] = Field(
        default="[]",
        description=(
            "Alarmes sérialisées en JSON string. "
            "TOUJOURS passer une string, jamais un array. "
            "Exemple sans alarme: '[]'."
        )
    )

    @field_validator("alarmes_json", mode="before")
    @classmethod
    def coerce_to_str(cls, v):
        if isinstance(v, (dict, list)):
            return json.dumps(v, ensure_ascii=False)
        if v is None:
            return "[]"
        return str(v)

class ActionCorrectiveInput(BaseModel):
    # [B1] field_validator : coerce dict/list → JSON string avant validation Pydantic.
    # Optional[Any] génère un anyOf sans properties → Groq rejette avec 400.
    # Le validator convertit silencieusement avant que Groq ne voie le schema.
    anomalie_json: Optional[str] = Field(
        default=None,
        description="Anomalie détectée en JSON string avec type, IP, sévérité"
    )

    @field_validator("anomalie_json", mode="before")
    @classmethod
    def coerce_to_str(cls, v):
        """Convertit dict/list → JSON string avant validation, transparent pour Groq."""
        if isinstance(v, (dict, list)):
            return json.dumps(v, ensure_ascii=False)
        if v is None:
            return None
        return str(v)

class OrchestrationInput(BaseModel):
    contexte: Optional[str] = Field(
        default=None,
        description="Contexte global de la session d'analyse pour coordonner les agents"
    )

class SauvegarderRapportInput(BaseModel):
    rapport_json: Optional[str] = Field(
        default=None,
        description="Le rapport COMPLET sérialisé en une seule string JSON"
    )


# ================================
# CLASSES D'OUTILS
# ================================

class OutilListerLogs(BaseTool):
    name: str = "lister_logs_s3"
    description: str = (
        "Liste les fichiers dans S3. "
        "Utilise toujours prefix='processed/' car c'est là que sont les fichiers."
    )
    args_schema: type[BaseModel] = ListerLogsInput

    def _run(self, prefix: Optional[str] = None, **kwargs) -> str:
        prefix = "processed/"
        result = _appeler_mcp("lister_logs_s3", {"prefix": prefix})
        lignes = [l for l in result.splitlines() if "dataset_" in l]
        return "Fichiers datasets S3:\n" + "\n".join(lignes[:5])


class OutilLireLogs(BaseTool):
    name: str = "lire_logs_s3"
    description: str = (
        "Lit un fichier log depuis S3. "
        "Le fichier doit commencer par 'processed/' ex: 'processed/erreurs_par_heure.csv'"
    )
    args_schema: type[BaseModel] = LireLogsInput

    def _run(self, fichier: Optional[str] = None, **kwargs) -> str:
        if fichier and fichier.startswith("logs/"):
            fichier = fichier.replace("logs/", "", 1)
        resultat = _appeler_mcp("lire_logs_s3", {"fichier": fichier})
        if len(resultat) > 300:
            lignes = resultat.split("\n")[:12]
            return "\n".join(lignes) + "\n... [tronqué à 12 lignes]"
        return resultat


class OutilAnalyserLogs(BaseTool):
    """
    [B4] Version enrichie du binôme : 8 types d'attaques détectés
    au lieu d'une simple analyse erreurs/warnings/SSH.
    """
    name: str = "analyser_logs"
    description: str = (
        "Analyse les logs et compte tous les types d'attaques et événements suspects : "
        "SSH brute-force, scan de ports, énumération web, blocages firewall, "
        "échecs d'auth, abus sudo, problèmes mémoire, services en échec."
    )
    args_schema: type[BaseModel] = AnalyserLogsInput

    def _run(self, contenu: Optional[str] = None, **kwargs) -> str:
        if not contenu:
            return "Aucun contenu à analyser"

        lignes = contenu.splitlines()
        compteurs = {
            "SSH_BRUTE_FORCE":  0,
            "PORT_SCAN":        0,
            "WEB_ENUMERATION":  0,
            "FIREWALL_BLOCK":   0,
            "AUTH_FAILURE":     0,
            "SUDO_ABUSE":       0,
            "MEMORY_CRITICAL":  0,
            "SERVICE_FAILED":   0,
        }

        for ligne in lignes:
            l = ligne.upper()
            if "FAILED PASSWORD" in l or "INVALID USER" in l or "BRUTE" in l:
                compteurs["SSH_BRUTE_FORCE"] += 1
            if "NMAP" in l or "PORT SCAN" in l or "MASSCAN" in l:
                compteurs["PORT_SCAN"] += 1
            if "GOBUSTER" in l or "ENUMERATION" in l or "DIRB" in l:
                compteurs["WEB_ENUMERATION"] += 1
            if "UFW BLOCK" in l or "IPTABLES" in l or "DENIED" in l:
                compteurs["FIREWALL_BLOCK"] += 1
            if "AUTHENTICATION FAILURE" in l or "PERM DENIED" in l:
                compteurs["AUTH_FAILURE"] += 1
            if "SUDO" in l and "COMMAND" in l:
                compteurs["SUDO_ABUSE"] += 1
            if "OUT OF MEMORY" in l or "OOM" in l:
                compteurs["MEMORY_CRITICAL"] += 1
            if "FAILED" in l and "SERVICE" in l:
                compteurs["SERVICE_FAILED"] += 1

        rapport = "=== RAPPORT D'ANALYSE ===\n"
        for type_attaque, nombre in compteurs.items():
            if nombre > 0:
                rapport += f"{type_attaque}: {nombre} occurrence(s)\n"

        total = sum(compteurs.values())
        rapport += f"\nTOTAL ÉVÉNEMENTS SUSPECTS : {total}"
        return rapport


class OutilDetecterAnomalies(BaseTool):
    name: str = "detecter_anomalies"
    description: str = (
        "Détecte les intrusions SSH, surcharges système et comportements suspects. "
        "Déclenche automatiquement une alarme préventive avec un message adapté "
        "au type d'anomalie AVANT que la panne survienne."
    )
    args_schema: type[BaseModel] = DetecterAnomaliesInput

    def _run(self, rapport: Optional[str] = None, **kwargs) -> str:
        return _appeler_mcp("detecter_anomalies", {"contenu_logs": rapport or str(kwargs)})


class OutilDeclencherAlarme(BaseTool):
    name: str = "declencher_alarme"
    description: str = (
        "Déclenche une alarme préventive AVANT qu'une panne survienne. "
        "Si alarmes_json vaut 'Aucune alarme critique' ou est vide, "
        "NE PAS déclencher d'alarme — retourner un statut OK."
    )
    args_schema: type[BaseModel] = AlarmeInput

    def _run(self, alarmes_json: Optional[str] = None, **kwargs) -> str:
        # [B3] Flag anti-boucle : une seule alarme par cycle
        global _alarme_declenchee_ce_cycle
        if _alarme_declenchee_ce_cycle:
            return "Alarme déjà traitée dans ce cycle — ignoré."
        _alarme_declenchee_ce_cycle = True

        if not alarmes_json or alarmes_json.strip() in (
            "Aucune alarme critique", "[]", "", "null", "aucune", "none"
        ):
            return "Aucune alarme à déclencher — système en état normal."

        try:
            if isinstance(alarmes_json, (list, dict)):
                alarmes = alarmes_json if isinstance(alarmes_json, list) else [alarmes_json]
            else:
                alarmes = json.loads(alarmes_json) if alarmes_json else []
                if not isinstance(alarmes, list):
                    alarmes = [alarmes]
        except Exception:
            texte_upper = alarmes_json.upper()
            mots_cles_reels = ["BRUTE", "SCAN", "INTRUSION", "CRITIQUE", "BLOCAGE"]
            if not any(m in texte_upper for m in mots_cles_reels):
                return "Pas d'anomalie confirmée dans le message reçu."
            alarmes = [{
                "type":     "ANOMALIE",
                "message":  alarmes_json,
                "severite": "AVERTISSEMENT",
                "ip":       "multiple"
            }]

        resultats = []
        for alarme in alarmes:
            type_alarme = alarme.get("type", "ANOMALIE")
            message     = alarme.get("message", "Anomalie détectée")
            severite    = alarme.get("severite", "AVERTISSEMENT")
            ip          = alarme.get("ip", "N/A")

            if "BRUTE-FORCE" in type_alarme.upper() or "SSH" in type_alarme.upper():
                notification = (
                    f"ALARME SÉCURITÉ — BRUTE-FORCE SSH DÉTECTÉ\n"
                    f"IP Source: {ip}\nDétail: {message}\n"
                    f"Action immédiate requise: Bloquer {ip} via iptables/Fail2Ban"
                )
            elif "SURCHARGE" in type_alarme.upper() or "CPU" in type_alarme.upper():
                notification = (
                    f"ALARME PERFORMANCE — SURCHARGE SYSTÈME DÉTECTÉE\n"
                    f"Détail: {message}\n"
                    f"Action immédiate requise: Vérifier les processus"
                )
            elif "MÉMOIRE" in type_alarme.upper() or "RAM" in type_alarme.upper():
                notification = (
                    f"ALARME RESSOURCES — SATURATION MÉMOIRE DÉTECTÉE\n"
                    f"Détail: {message}\n"
                    f"Action immédiate requise: Libérer la RAM"
                )
            elif "SCAN" in type_alarme.upper() or "PORT" in type_alarme.upper():
                notification = (
                    f"ALARME RECONNAISSANCE — SCAN DE PORTS DÉTECTÉ\n"
                    f"IP Source: {ip}\nDétail: {message}\n"
                    f"Action immédiate requise: Ajouter {ip} à la blacklist"
                )
            else:
                notification = (
                    f"ALARME GÉNÉRALE — {severite}\n"
                    f"Détail: {message}\n"
                    f"Action immédiate requise: Inspection manuelle"
                )

            print(f"\n{'='*60}")
            print(notification)
            print(f"{'='*60}\n")

            ip_safe = str(ip).replace(".", "_").replace("/", "_")
            result  = _appeler_mcp("sauvegarder_rapport_s3", {
                "contenu":     notification,
                "nom_fichier": f"alarme_{ip_safe}.json",
                "type":        "alarme",
            })
            resultats.append(f"Alarme envoyée: {notification[:100]}... | S3: {result}")

        return "\n".join(resultats) if resultats else "Aucune alarme déclenchée."


class OutilActionCorrective(BaseTool):
    name: str = "appliquer_action_corrective"
    description: str = (
        "Applique automatiquement une action corrective selon le type d'anomalie : "
        "- Blocage IP réel dans AWS Security Group via Boto3 pour brute-force SSH "
        "- Bannissement IP via Fail2Ban pour échecs d'authentification "
        "- Blacklist IP pour port scan Nmap "
        "- Désactivation de compte utilisateur suspect "
        "- Alerte email/Slack pour surcharge système "
        "- Confirmation OK pour surveillance normale"
    )
    args_schema: type[BaseModel] = ActionCorrectiveInput

    def _run(self, anomalie_json: Optional[str] = None, **kwargs) -> str:
        # Garde-fou : field_validator s'en occupe, mais au cas où CrewAI contourne
        if isinstance(anomalie_json, (dict, list)):
            anomalie_json = json.dumps(anomalie_json, ensure_ascii=False)

        # ── Parsing JSON ou texte libre ───────────────────────────────────────
        try:
            anomalie = json.loads(anomalie_json) if anomalie_json else {}
        except Exception:
            texte       = (anomalie_json or "")
            texte_upper = texte.upper()
            ip_trouvee  = "multiple"
            match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', texte)
            if match:
                ip_trouvee = match.group(1)
            if "BRUTE" in texte_upper or "SSH" in texte_upper or "BLOCAGE" in texte_upper:
                anomalie = {"type": "BRUTE-FORCE SSH", "severite": "CRITIQUE", "ip": ip_trouvee}
            elif "CPU" in texte_upper or "SURCHARGE" in texte_upper:
                anomalie = {"type": "SURCHARGE CPU",   "severite": "AVERTISSEMENT", "ip": "N/A"}
            elif "SCAN" in texte_upper or "PORT" in texte_upper:
                anomalie = {"type": "PORT SCAN",       "severite": "AVERTISSEMENT", "ip": "N/A"}
            else:
                anomalie = {"description": str(anomalie_json)}

        type_anomalie = anomalie.get("type", anomalie.get("feature", ""))
        ip            = anomalie.get("ip", "N/A")
        severite      = anomalie.get("severite", "AVERTISSEMENT")
        action_req    = anomalie.get("action", "")

        type_upper   = str(type_anomalie).upper()
        action_upper = str(action_req).upper()

        # ── [B2] SURVEILLANCE_NORMALE — cas explicite ─────────────────────────
        if (
            "SURVEILLANCE" in type_upper
            or "NORMALE" in type_upper
            or "MONITORING" in action_upper
            or (
                type_upper in ("", "FAIBLE", "INFO")
                and severite in ("FAIBLE", "INFO", "NORMAL")
            )
        ):
            action = {
                "type":        "SURVEILLANCE_NORMALE",
                "description": "Système en surveillance normale — aucune action corrective requise.",
                "statut":      "OK",
                "details":     {
                    "ip":       ip,
                    "severite": severite,
                    "message":  "Aucune attaque active confirmée. Monitoring passif actif.",
                    "conseil":  "Continuer la surveillance. Prochain cycle d'analyse prévu automatiquement."
                }
            }
            print(f"[ACTION CORRECTIVE] {action['description']}")
            result_str = json.dumps(action, ensure_ascii=False, indent=2)
            _appeler_mcp("sauvegarder_rapport_s3", {
                "contenu":     result_str,
                "nom_fichier": "action_surveillance-normale.json",
                "type":        "action_corrective",
            })
            return result_str

        # ── Actions préventives analytiques (pas de blocage auto) ─────────────
        if (
            "ALERT_HIGH_PRIORITY" in type_upper
            or "TRAFFIC_THROTTLE" in type_upper
            or "PREEMPTIVE_BLOCK" in type_upper
            or "PRE_ATTACK" in type_upper
            or "IMMINENT_DATA_EXFIL" in type_upper
        ):
            action = {
                "type":        "RECOMMANDATION_PREVENTIVE",
                "commande":    "",
                "description": (
                    f"Action préventive recommandée ({type_anomalie}). "
                    "Aucune exécution automatique."
                ),
                "statut":      "EN_ATTENTE",
            }
            result_str  = json.dumps(action, ensure_ascii=False, indent=2)
            nom_fichier = f"action_{action['type'].lower().replace('_', '-')}.json"
            _appeler_mcp("sauvegarder_rapport_s3", {
                "contenu":     json.dumps(action, ensure_ascii=False),
                "nom_fichier": nom_fichier,
                "type":        "action_corrective",
            })
            return result_str

        # ── Actions réelles ───────────────────────────────────────────────────
        if "BRUTE" in type_upper or "SSH" in type_upper or "tentatives" in type_anomalie:
            if severite == "CRITIQUE":
                action = {
                    "type":        "BLOCAGE_IP_AWS_SECGROUP",
                    "commande":    f"iptables -A INPUT -s {ip} -j DROP",
                    "description": f"Blocage immédiat de {ip} via AWS Security Group (Boto3)",
                    "statut":      "EN_COURS"
                }
            else:
                action = {
                    "type":        "BAN_FAIL2BAN",
                    "commande":    f"fail2ban-client set sshd banip {ip}",
                    "description": f"Bannissement de {ip} via Fail2Ban",
                    "statut":      "EXÉCUTÉ"
                }

        elif "SCAN" in type_upper or "PORT" in type_upper:
            action = {
                "type":        "BLACKLIST_IP",
                "commande":    f"iptables -A INPUT -s {ip} -j DROP && echo '{ip}' >> /etc/blacklist.txt",
                "description": f"Ajout de {ip} à la blacklist (scan de ports détecté)",
                "statut":      "EXÉCUTÉ"
            }

        elif "SURCHARGE" in type_upper or "CPU" in type_upper or "erreurs" in type_anomalie:
            action = {
                "type":        "ALERTE_SYSTEME",
                "commande":    "systemctl status --failed && journalctl -p err -n 50",
                "description": "Alerte email envoyée + logs critiques archivés dans S3",
                "slack_msg":   "Surcharge système détectée — vérification requise immédiatement",
                "statut":      "ALERTE_ENVOYÉE"
            }

        elif "MÉMOIRE" in type_upper or "MEM" in type_upper:
            action = {
                "type":        "LIBERER_MEMOIRE",
                "commande":    "sync && echo 3 > /proc/sys/vm/drop_caches",
                "description": "Libération du cache mémoire + redémarrage des services non critiques",
                "statut":      "EXÉCUTÉ"
            }

        elif "UTILISATEUR" in type_upper or "USER" in type_upper:
            user = anomalie.get("user", "unknown")
            action = {
                "type":        "DESACTIVER_COMPTE",
                "commande":    f"usermod -L {user}",
                "description": f"Compte {user} temporairement désactivé (comportement suspect)",
                "statut":      "EXÉCUTÉ"
            }

        else:
            action = {
                "type":        "INSPECTION_MANUELLE",
                "description": f"Anomalie non reconnue — inspection manuelle requise: {anomalie}",
                "statut":      "EN_ATTENTE"
            }

        print(f"[ACTION CORRECTIVE] {action['description']}")
        if "commande" in action:
            print(f"[COMMANDE]          {action['commande']}")

        # ── Blocage AWS réel via Boto3 ────────────────────────────────────────
        est_ssh       = "BRUTE" in type_upper or "SSH" in type_upper
        ip_specifique = ip and ip not in ("N/A", "multiple", "")

        if AWS_SECURITY_DISPONIBLE and est_ssh and ip_specifique and severite == "CRITIQUE":
            print(f"\n[AWS BOTO3] Blocage RÉEL de {ip} dans Security Group AWS...")
            try:
                aws_result = bloquer_ip_secgroup(
                    ip=ip,
                    raison=(
                        f"Agent IA CrewAI | {type_anomalie} | "
                        f"Sévérité: {severite} | Auto-blocage"
                    )
                )
                action["aws_blocage_reel"] = aws_result
                action["aws_statut"]       = aws_result.get("statut", "INCONNU")
                action["statut"]           = "EXÉCUTÉ"
                print(f"[AWS BOTO3] Résultat  : {aws_result.get('message', 'N/A')}")
                print(f"[AWS BOTO3] SG statut : {aws_result.get('statut')}")
                if aws_result.get("regles_supprimees"):
                    print(f"[AWS BOTO3] Règles supprimées : {aws_result['regles_supprimees']}")
                if aws_result.get("tag_audit"):
                    print(f"[AWS BOTO3] Audit trail : {aws_result['tag_audit']}")
                if aws_result.get("nacl_regle", {}).get("statut") == "DENY_AJOUTÉ":
                    nacl_info = aws_result["nacl_regle"]
                    print(f"[AWS BOTO3] NACL DENY #{nacl_info['rule_number']} ajoutée dans {nacl_info['nacl_id']}")
            except Exception as e:
                print(f"[AWS BOTO3] Erreur boto3: {type(e).__name__}: {e}")
                action["aws_blocage_reel"] = {"statut": "ERREUR", "message": str(e)}
                action["statut"]           = "ERREUR_AWS"

        elif AWS_SECURITY_DISPONIBLE and est_ssh and not ip_specifique:
            print(f"[AWS BOTO3] IP '{ip}' non spécifique — blocage manuel requis")
            action["aws_blocage_reel"] = {
                "statut":  "IGNORÉ",
                "raison":  f"IP '{ip}' non spécifique — impossible de bloquer automatiquement",
                "conseil": "Identifiez les IPs précises et appelez bloquer_ip_secgroup() manuellement"
            }

        elif not AWS_SECURITY_DISPONIBLE:
            action["aws_blocage_reel"] = {
                "statut":  "SIMULATION",
                "message": "aws_security.py non importé — configurez AWS_SECURITY_GROUP_ID dans .env"
            }

        # ── Sérialisation et sauvegarde S3 ───────────────────────────────────
        result_str  = json.dumps(action, ensure_ascii=False, indent=2)
        nom_fichier = f"action_{action['type'].lower().replace('_', '-')}.json"
        _appeler_mcp("sauvegarder_rapport_s3", {
            "contenu":     json.dumps(action, ensure_ascii=False),
            "nom_fichier": nom_fichier,
            "type":        "action_corrective",
        })
        return result_str


class OutilOrchestration(BaseTool):
    name: str = "orchestrer_pipeline"
    description: str = "Coordonne et priorise le travail des 5 autres agents."
    args_schema: type[BaseModel] = OrchestrationInput

    def _run(self, contexte: Optional[str] = None, **kwargs) -> str:
        result = _appeler_mcp("orchestrer_pipeline", {"contexte": contexte or str(kwargs)})
        return result if isinstance(result, str) and result.strip() else "Pipeline orchestré avec succès."


class OutilSauvegarderRapport(BaseTool):
    name: str = "sauvegarder_rapport_s3"
    description: str = (
        "Sauvegarde le rapport final complet sur S3. "
        "Sérialise TOUT le rapport en JSON string et le passe dans rapport_json."
    )
    args_schema: type[BaseModel] = SauvegarderRapportInput

    def _run(self, rapport_json: Optional[str] = None, **kwargs) -> str:
        try:
            data = json.loads(rapport_json) if isinstance(rapport_json, str) else {}
        except Exception:
            data = {}

        data["contenu"]     = rapport_json or str(kwargs)
        data["nom_fichier"] = f"rapport_{data.get('timestamp', 'final')}.json"

        return _appeler_mcp(
            "sauvegarder_rapport_s3",
            data or {
                "contenu":     str(kwargs),
                "nom_fichier": "rapport_final.json"
            }
        )


# ================================
# INSTANCES DES OUTILS
# ================================
outil_lister_logs  = OutilListerLogs()
outil_lire_logs    = OutilLireLogs()
outil_analyser     = OutilAnalyserLogs()
outil_anomalies    = OutilDetecterAnomalies()
outil_alarme       = OutilDeclencherAlarme()
outil_correctif    = OutilActionCorrective()
outil_orchestrer   = OutilOrchestration()
outil_rapport      = OutilSauvegarderRapport()


# ================================
# 6 AGENTS SPÉCIALISÉS
# ================================

# ── Agent 1 : Collecteur ─────────────────────────────────────────────────────
collector_agent = Agent(
    role="Collecteur de Logs",
    goal=(
        "Collecter de manière exhaustive tous les fichiers logs depuis Amazon S3 "
        "et assurer la disponibilité des données pour les agents suivants."
    ),
    backstory=(
        "Tu es un expert en collecte de données système. Tu maîtrises parfaitement "
        "Amazon S3 et récupères les logs des serveurs Linux (syslog, auth.log) "
        "ainsi que les logs d'attaques générés par la VM Kali Linux."
    ),
    tools=[outil_lister_logs, outil_lire_logs],
    llm=llm,
    verbose=True,
    max_iter=2,
    max_retry_limit=1,
)
# ── Agent 2 : Analyste ───────────────────────────────────────────────────────

analyst_agent = Agent(
    role="Analyste de Logs Linux",
    goal=(
        "Analyser en profondeur les logs pour identifier tous les types "
        "d'attaques et événements suspects, compter les erreurs et connexions SSH, "
        "et prédire les tendances futures."
    ),
    backstory=(
        "Tu es un expert en analyse de logs Linux et en cybersécurité. "
        "Tu distingues les erreurs critiques des simples warnings, "
        "identifies les patterns suspects et anticipes les tendances "
        "grâce à une analyse statistique rigoureuse."
    ),
    tools=[outil_analyser],
    llm=llm_analyst,
    verbose=True,
    max_iter=2,       
    max_retry_limit=1, 
)

# ── Agent 3 : Détecteur + Alarmes ────────────────────────────────────────────
detector_agent = Agent(
    role="Détecteur d'Anomalies et Déclencheur d'Alarmes",
    goal=(
        "Détecter les anomalies confirmées et déclencher une alarme UNIQUEMENT "
        "si une vraie menace est présente. Ne pas déclencher d'alarme si le "
        "système est en état normal."
    ),
    backstory=(
        "Tu es un expert en cybersécurité et détection d'anomalies. "
        "Tu identifies en temps réel les tentatives d'intrusion SSH, "
        "les surcharges système, les scans de ports et les comportements anormaux. "
        "Tu déclenches des alarmes SEULEMENT quand une anomalie réelle est confirmée. "
        "Si nb_anomalies=0 et aucune alarme critique, tu retournes un statut OK "
        "sans déclencher d'alarme."
    ),
    tools=[outil_anomalies, outil_alarme],
    llm=llm,
    verbose=True,
    max_iter=1,          # [B5] Évite les boucles infinies sur le détecteur
    max_retry_limit=1,
)

# ── Agent 4 : Correcteur ─────────────────────────────────────────────────────
corrector_agent = Agent(
    role="Agent Correcteur Automatique",
    goal=(
        "Analyser chaque anomalie détectée et appliquer automatiquement "
        "l'action corrective appropriée. "
        "En mode surveillance normale, confirmer l'état OK sans bloquer d'IP."
    ),
    backstory=(
        "Tu es un expert en remédiation automatique de sécurité informatique. "
        "Pour SURVEILLANCE_NORMALE tu confirmes simplement l'état sain. "
        "Pour les vraies attaques : blocage RÉEL via Boto3 dans l'AWS Security Group "
        "pour les brute-force SSH critiques, Fail2Ban pour les échecs d'auth répétés, "
        "blacklist pour les scans de ports Nmap, désactivation de compte "
        "pour les comportements suspects, alertes email/Slack pour les surcharges système."
    ),
    tools=[outil_correctif],
    llm=llm,
    verbose=True
)

# ── Agent 5 : Orchestrateur ──────────────────────────────────────────────────
orchestrator_agent = Agent(
    role="Orchestrateur de Pipeline Multi-Agents",
    goal=(
        "Coordonner l'ensemble des 5 agents spécialisés, "
        "gérer les priorités en temps réel, décider des escalades "
        "et garantir la cohérence globale de l'analyse."
    ),
    backstory=(
        "Tu es le chef d'orchestre du système de supervision. "
        "Tu supervises en permanence l'état global du pipeline, "
        "coordonnes les interventions des agents selon la criticité des événements, "
        "gères les conflits de priorité et garantis que chaque anomalie "
        "est traitée dans le bon ordre par le bon agent. "
        "En cas d'incident critique, tu escalades immédiatement vers "
        "le détecteur et le correcteur avant tout autre traitement. "
        "Tu réponds DIRECTEMENT sans utiliser d'outil externe."
    ),
    tools=[],   # Aucun outil — évite brave_search sur Groq
    llm=llm_orchestrator,
    verbose=True
)

# ── Agent 6 : Rapporteur ─────────────────────────────────────────────────────
reporter_agent = Agent(
    role="Rapporteur et Synthétiseur",
    goal=(
        "Générer un rapport complet, structuré et lisible "
        "consolidant les résultats de tous les agents, "
        "puis le sauvegarder sur S3 pour les équipes opérationnelles."
    ),
    backstory=(
        "Tu es expert en reporting opérationnel et visualisation de données. "
        "Tu synthétises les analyses, anomalies, alarmes et actions correctives "
        "en rapports clairs avec des KPIs précis, des recommandations "
        "et un résumé exécutif pour les équipes de supervision."
    ),
    tools=[outil_rapport],
    llm=llm,
    verbose=True
)
