# src/mcp/mcp_server.py — FINAL (ta version + UTF-8 fix binôme)

import asyncio
import json
import sys
import os
from datetime import datetime

# Force l'encodage UTF-8 (fix binôme, très utile sous Windows)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

# Ajouter la racine du projet au path
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp import types
from dotenv import load_dotenv

# imports locaux
from src.tools import linux_tools, s3_tools

load_dotenv()

# les variables S3 sont gérées dans s3_tools ; on peut les réexporter si besoin
BUCKET_NAME = os.getenv("S3_BUCKET_NAME")

# Créer le serveur MCP
app = Server("linux-supervision-server")


# ================================
# LISTE DES OUTILS DISPONIBLES
# ================================
@app.list_tools()
async def list_tools():
    tools = [
        types.Tool(
            name="lire_logs_s3",
            description="Lit et récupère les logs Linux depuis Amazon S3",
            inputSchema={
                "type": "object",
                "properties": {
                    "fichier": {"type": "string", "description": "Nom du fichier log dans S3"},
                    "key": {"type": "string", "description": "Alias de fichier (compatibilité outils)"},
                },
                "required": [],
            },
        ),
        types.Tool(
            name="lister_logs_s3",
            description="Liste tous les fichiers logs disponibles dans S3",
            inputSchema={
                "type": "object",
                "properties": {
                    "prefix": {"type": "string", "description": "Préfixe optionnel, ex: processed/"},
                },
                "required": [],
            },
        ),
        types.Tool(
            name="analyser_logs",
            description="Analyse les logs pour détecter erreurs et anomalies",
            inputSchema={
                "type": "object",
                "properties": {
                    "contenu_logs": {"type": "string", "description": "Contenu brut des logs à analyser"},
                    "contenu": {"type": "string", "description": "Alias de contenu (compatibilité outils)"},
                },
                "required": [],
            },
        ),
        types.Tool(
            name="detecter_anomalies",
            description="Détecte les anomalies : tentatives intrusion, pics erreurs, surcharge CPU",
            inputSchema={
                "type": "object",
                "properties": {
                    "donnees": {"type": "string", "description": "Données analysées en JSON"},
                    "rapport": {"type": "string", "description": "Alias de données (compatibilité outils)"},
                },
                "required": [],
            },
        ),
        types.Tool(
            name="sauvegarder_rapport_s3",
            description="Sauvegarde le rapport final sur Amazon S3",
            inputSchema={
                "type": "object",
                "properties": {
                    "contenu": {"type": "string", "description": "Contenu du rapport"},
                    "nom_fichier": {"type": "string", "description": "Nom du fichier rapport"},
                    "rapport_json": {"type": "string", "description": "Alias JSON compact (compatibilité outils)"},
                },
                "required": [],
            },
        ),
        types.Tool(
            name="run_ssh_command",
            description="Exécute une commande arbitraire sur un serveur Linux via SSH",
            inputSchema={
                "type": "object",
                "properties": {
                    "host": {"type": "string"},
                    "username": {"type": "string"},
                    "password": {"type": "string"},
                    "key_path": {"type": "string"},
                    "port": {"type": "integer"},
                    "command": {"type": "string"},
                },
                "required": ["host", "username", "command"],
            },
        ),
        types.Tool(
            name="get_system_metrics",
            description="Récupère CPU, mémoire et disque depuis un serveur via SSH",
            inputSchema={
                "type": "object",
                "properties": {
                    "host": {"type": "string"},
                    "username": {"type": "string"},
                    "password": {"type": "string"},
                    "key_path": {"type": "string"},
                    "port": {"type": "integer"},
                },
                "required": ["host", "username"],
            },
        ),
        # Point fort ta version: outil d'orchestration "léger"
        types.Tool(
            name="orchestrer_pipeline",
            description="Retourne un résumé court de l'orchestration demandée",
            inputSchema={
                "type": "object",
                "properties": {"contexte": {"type": "string"}},
                "required": [],
            },
        ),
    ]

    return tools


# ================================
# LOGIQUE DES OUTILS
# ================================
@app.call_tool()
async def call_tool(name: str, arguments: dict):
    try:
        # OUTIL 1 : Lire un fichier log depuis S3
        if name == "lire_logs_s3":
            try:
                fichier = arguments.get("fichier") or arguments.get("key")
                if not fichier:
                    return [types.TextContent(type="text", text="Erreur: paramètre 'fichier' manquant.")]
                contenu = s3_tools.read_object(fichier)
                snippet = contenu[:1200]
                return [types.TextContent(type="text", text=f"Logs récupérés depuis S3 (extrait):\n{snippet}")]
            except Exception as e:
                return [types.TextContent(type="text", text=f"Erreur lecture S3: {str(e)}")]

        # OUTIL 2 : Lister les fichiers logs dans S3
        if name == "lister_logs_s3":
            try:
                prefix = arguments.get("prefix")
                fichiers = s3_tools.list_objects(prefix=prefix) if prefix else s3_tools.list_objects()
                fichiers = fichiers[:20]
                return [types.TextContent(type="text", text="Fichiers disponibles dans S3:\n" + "\n".join(fichiers))]
            except Exception as e:
                return [types.TextContent(type="text", text=f"Erreur listage S3: {str(e)}")]

        # OUTIL 3 : Analyser les logs
        if name == "analyser_logs":
            logs = arguments.get("contenu_logs") or arguments.get("contenu") or ""
            lignes = logs.split("\n")

            analyse = {
                "total_lignes": len(lignes),
                "erreurs": [],
                "warnings": [],
                "connexions_ssh": [],
                "timestamp": datetime.now().isoformat(),
            }

            for ligne in lignes:
                ligne_lower = ligne.lower()
                if "error" in ligne_lower or "failed" in ligne_lower:
                    analyse["erreurs"].append(ligne[:200])
                elif "warning" in ligne_lower or "warn" in ligne_lower:
                    analyse["warnings"].append(ligne[:200])
                elif "ssh" in ligne_lower or "accepted" in ligne_lower:
                    analyse["connexions_ssh"].append(ligne[:200])

            resume = (
                "ANALYSE DES LOGS:\n"
                f"- Total lignes: {analyse['total_lignes']}\n"
                f"- Erreurs: {len(analyse['erreurs'])}\n"
                f"- Warnings: {len(analyse['warnings'])}\n"
                f"- Connexions SSH: {len(analyse['connexions_ssh'])}\n"
                "Top erreurs:\n"
                + "\n".join(analyse["erreurs"][:3])
            )

            return [types.TextContent(type="text", text=resume)]

        # OUTIL 4 : Détecter anomalies
        if name == "detecter_anomalies":
            donnees = str(arguments.get("donnees") or arguments.get("rapport") or "")
            anomalies = []

            if "error" in donnees.lower():
                nb_erreurs = donnees.lower().count("error")
                if nb_erreurs > 10:
                    anomalies.append(f"CRITIQUE: {nb_erreurs} erreurs detectees")

            if "failed password" in donnees.lower():
                anomalies.append("SECURITE: Tentatives de connexion echouees detectees")

            if "invalid user" in donnees.lower():
                anomalies.append("INTRUSION: Utilisateur invalide detecte")

            if "out of memory" in donnees.lower():
                anomalies.append("MEMOIRE: Probleme memoire detecte")

            if not anomalies:
                anomalies.append("OK: Aucune anomalie critique detectee")

            return [types.TextContent(type="text", text="ANOMALIES DETECTEES:\n" + "\n".join(anomalies))]

        # OUTIL 5 : Sauvegarder rapport sur S3
        if name == "sauvegarder_rapport_s3":
            try:
                contenu = arguments.get("contenu") or arguments.get("rapport_json") or ""
                nom_fichier = arguments.get(
                    "nom_fichier",
                    f"rapport_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                )
                s3_tools.save_report(content=contenu, key=f"rapports/{nom_fichier}")
                return [types.TextContent(type="text", text=f"Rapport sauvegarde sur S3: rapports/{nom_fichier}")]
            except Exception as e:
                return [types.TextContent(type="text", text=f"Erreur sauvegarde S3: {str(e)}")]

        # OUTIL 6 : commande SSH générique
        if name == "run_ssh_command":
            host = arguments.get("host")
            username = arguments.get("username")
            password = arguments.get("password")
            key_path = arguments.get("key_path")
            port = arguments.get("port", 22)
            command = arguments.get("command")
            output = linux_tools.run_ssh_command(
                host=host,
                username=username,
                password=password,
                key_path=key_path,
                command=command,
                port=port,
            )
            return [types.TextContent(type="text", text=output)]

        # OUTIL 7 : collecter métriques système via SSH
        if name == "get_system_metrics":
            host = arguments.get("host")
            username = arguments.get("username")
            password = arguments.get("password")
            key_path = arguments.get("key_path")
            port = arguments.get("port", 22)
            metrics = linux_tools.get_system_metrics(
                host=host,
                username=username,
                password=password,
                key_path=key_path,
                port=port,
            )
            return [types.TextContent(type="text", text=json.dumps(metrics, indent=2, ensure_ascii=False))]

        # OUTIL 8 : orchestration (léger)
        if name == "orchestrer_pipeline":
            contexte = arguments.get("contexte", "")
            resume = f"Orchestration OK. Contexte: {contexte[:200]}"
            return [types.TextContent(type="text", text=resume)]

        return [types.TextContent(type="text", text=f"Outil inconnu: {name}")]

    except Exception as e:
        return [types.TextContent(type="text", text=f"Erreur MCP: {type(e).__name__}: {e}")]


# Lancer le serveur
async def main():
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())