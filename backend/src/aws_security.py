"""
src/aws_security.py
Module Boto3 — Blocage d'IP malveillantes dans un AWS Security Group.

Fonctionnalités :
  - bloquer_ip_secgroup(ip)     : Ajoute une règle DENY (ingress suppression) dans le SG
  - debloquer_ip_secgroup(ip)   : Retire la règle de blocage (rollback)
  - lister_ips_bloquees()       : Liste toutes les IPs actuellement taguées comme bloquées
  - verifier_ip_bloquee(ip)     : Vérifie si une IP est déjà bloquée

Stratégie AWS :
  AWS Security Groups sont des listes blanches (allow-only).
  Pour "bloquer" une IP on :
    1. Retire toute règle ALLOW existante pour cette IP sur les ports critiques (22, 80, 443, 0-65535)
    2. Ajoute un Tag sur le SG pour tracer les IPs bloquées (audit trail)
    3. [Optionnel] Ajoute la règle dans une NACL (Network ACL) si configurée — les NACLs
       supportent les règles DENY explicites contrairement aux Security Groups.

Usage :
  from src.aws_security import bloquer_ip_secgroup
  resultat = bloquer_ip_secgroup("192.168.1.100")
  print(resultat)
"""

import boto3
import json
import os
import logging
from datetime import datetime, timezone
from typing import Optional
from botocore.exceptions import ClientError, NoCredentialsError, EndpointResolutionError
from dotenv import load_dotenv

load_dotenv()

# ─── Configuration ────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

# Variables d'environnement (à définir dans .env ou environment)
AWS_REGION        = os.getenv("AWS_REGION",           "eu-west-3")          # Paris par défaut
SECURITY_GROUP_ID = os.getenv("AWS_SECURITY_GROUP_ID", "sg-XXXXXXXXXXXXXXXXX")  # À remplacer
NACL_ID           = os.getenv("AWS_NACL_ID",           None)                 # Optionnel
AWS_ACCESS_KEY_ID     = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")

# Ports critiques à surveiller pour les règles d'entrée
PORTS_CRITIQUES = [22, 80, 443, 3306, 5432, 6379, 27017]

# Règle NACL de départ pour le blocage (numéro de règle décroissant pour priorité haute)
NACL_RULE_NUMBER_START = 50


# ─── Client Boto3 ─────────────────────────────────────────────────────────────
def _get_ec2_client():
    """Crée et retourne un client EC2 Boto3 configuré."""
    kwargs = {"region_name": AWS_REGION}
    if AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY:
        kwargs["aws_access_key_id"]     = AWS_ACCESS_KEY_ID
        kwargs["aws_secret_access_key"] = AWS_SECRET_ACCESS_KEY
    return boto3.client("ec2", **kwargs)


def _get_ec2_resource():
    """Crée et retourne une ressource EC2 Boto3 configurée."""
    kwargs = {"region_name": AWS_REGION}
    if AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY:
        kwargs["aws_access_key_id"]     = AWS_ACCESS_KEY_ID
        kwargs["aws_secret_access_key"] = AWS_SECRET_ACCESS_KEY
    return boto3.resource("ec2", **kwargs)


# ─── Fonction principale ───────────────────────────────────────────────────────
def bloquer_ip_secgroup(
    ip: str,
    security_group_id: Optional[str] = None,
    ports: Optional[list] = None,
    raison: str = "Blocage automatique — anomalie détectée par agent IA"
) -> dict:
    """
    Bloque une IP suspecte dans le Security Group AWS.

    Stratégie double :
      1. Supprime toute règle ALLOW entrant pour cette IP dans le Security Group
      2. Ajoute un Tag d'audit sur le Security Group pour tracer le blocage
      3. Si NACL_ID est configuré : ajoute une règle DENY explicite dans la Network ACL

    Args:
        ip (str)                  : IP à bloquer (ex: "192.168.1.100" ou "192.168.1.100/32")
        security_group_id (str)   : ID du SG cible (override env var AWS_SECURITY_GROUP_ID)
        ports (list)              : Liste de ports à vérifier (défaut: PORTS_CRITIQUES)
        raison (str)              : Raison du blocage pour l'audit trail

    Returns:
        dict: {
            "statut": "BLOQUÉE" | "DÉJÀ_BLOQUÉE" | "ERREUR",
            "ip": str,
            "security_group_id": str,
            "regles_supprimees": list,
            "tag_audit": str,
            "nacl_regle": dict | None,
            "timestamp": str,
            "message": str
        }
    """
    # Normalisation de l'IP (ajout /32 si CIDR absent)
    ip_cidr = ip if "/" in ip else f"{ip}/32"
    sg_id   = security_group_id or SECURITY_GROUP_ID
    ports   = ports or PORTS_CRITIQUES

    timestamp = datetime.now(timezone.utc).isoformat()
    resultat = {
        "statut":             "EN_COURS",
        "ip":                 ip,
        "ip_cidr":            ip_cidr,
        "security_group_id":  sg_id,
        "regles_supprimees":  [],
        "regles_existantes":  [],
        "tag_audit":          None,
        "nacl_regle":         None,
        "timestamp":          timestamp,
        "message":            ""
    }

    logger.info(f"[BLOCAGE] Début blocage IP {ip_cidr} dans Security Group {sg_id}")

    try:
        ec2 = _get_ec2_client()

        # ── Étape 1 : Récupérer les règles actuelles du Security Group ──────────
        response_sg = ec2.describe_security_groups(GroupIds=[sg_id])
        sg          = response_sg["SecurityGroups"][0]
        regles_entree = sg.get("IpPermissions", [])

        logger.info(f"[SG] {len(regles_entree)} règles d'entrée trouvées dans {sg_id}")

        # ── Étape 2 : Identifier et supprimer les règles ALLOW pour cette IP ─────
        regles_a_supprimer = []

        for regle in regles_entree:
            ranges_ipv4 = regle.get("IpRanges", [])
            for ip_range in ranges_ipv4:
                if ip_range.get("CidrIp") == ip_cidr:
                    regles_a_supprimer.append(regle)
                    port_from = regle.get("FromPort", "ALL")
                    port_to   = regle.get("ToPort",   "ALL")
                    proto     = regle.get("IpProtocol", "-1")
                    resultat["regles_existantes"].append(
                        f"{proto}:{port_from}-{port_to} depuis {ip_cidr}"
                    )
                    logger.info(f"[RÈGLE TROUVÉE] {proto} ports {port_from}-{port_to} pour {ip_cidr}")
                    break

        if regles_a_supprimer:
            # Suppression effective des règles ALLOW
            ec2.revoke_security_group_ingress(
                GroupId=sg_id,
                IpPermissions=regles_a_supprimer
            )
            resultat["regles_supprimees"] = resultat["regles_existantes"]
            logger.info(f"[OK] {len(regles_a_supprimer)} règle(s) supprimée(s) pour {ip_cidr}")
        else:
            logger.info(f"[INFO] Aucune règle ALLOW existante pour {ip_cidr} dans {sg_id}")

        # ── Étape 3 : Tag d'audit sur le Security Group ──────────────────────────
        # Le tag liste les IPs bloquées pour l'audit trail et la traçabilité
        try:
            # Récupérer le tag existant des IPs bloquées
            ips_bloquees_actuelles = []
            for tag in sg.get("Tags", []):
                if tag["Key"] == "IPs-Bloquees":
                    try:
                        ips_bloquees_actuelles = json.loads(tag["Value"])
                    except Exception:
                        ips_bloquees_actuelles = tag["Value"].split(",")
                    break

            # Ajouter la nouvelle IP si pas déjà présente
            if ip_cidr not in ips_bloquees_actuelles:
                ips_bloquees_actuelles.append(ip_cidr)

            # Mise à jour du tag (limité à 256 chars pour AWS)
            tag_value = json.dumps(ips_bloquees_actuelles)
            if len(tag_value) > 256:
                # Garder les 10 dernières IPs bloquées uniquement
                ips_bloquees_actuelles = ips_bloquees_actuelles[-10:]
                tag_value = json.dumps(ips_bloquees_actuelles)

            ec2.create_tags(
                Resources=[sg_id],
                Tags=[
                    {
                        "Key":   "IPs-Bloquees",
                        "Value": tag_value
                    },
                    {
                        "Key":   "Dernier-Blocage",
                        "Value": f"{ip} | {timestamp} | {raison[:100]}"
                    },
                    {
                        "Key":   "Agent-IA-Supervision",
                        "Value": "CrewAI-SecurityAgent"
                    }
                ]
            )
            resultat["tag_audit"] = f"Tag 'IPs-Bloquees' mis à jour : {tag_value}"
            logger.info(f"[TAG] Audit trail mis à jour sur {sg_id}")

        except ClientError as tag_err:
            logger.warning(f"[WARN] Tag audit échoué: {tag_err}")
            resultat["tag_audit"] = f"Tag échoué: {str(tag_err)}"

        # ── Étape 4 : NACL (Network ACL) — règle DENY explicite ─────────────────
        # Les NACLs supportent les règles DENY contrairement aux Security Groups
        if NACL_ID:
            resultat["nacl_regle"] = _bloquer_ip_dans_nacl(ec2, ip_cidr, raison)
        else:
            resultat["nacl_regle"] = {
                "statut":  "NON_CONFIGURÉ",
                "message": "NACL_ID non défini dans .env — blocage SG uniquement"
            }

        # ── Résultat final ───────────────────────────────────────────────────────
        if regles_a_supprimer:
            resultat["statut"]  = "BLOQUÉE"
            resultat["message"] = (
                f"✅ IP {ip} bloquée avec succès : "
                f"{len(regles_a_supprimer)} règle(s) ALLOW supprimée(s) du SG {sg_id}"
            )
        else:
            resultat["statut"]  = "BLOQUÉE_NACL_UNIQUEMENT" if NACL_ID else "AUCUNE_REGLE_ALLOW"
            resultat["message"] = (
                f"ℹ️ IP {ip} : aucune règle ALLOW à supprimer dans {sg_id}. "
                f"{'Règle DENY ajoutée dans NACL.' if NACL_ID else 'Ajout possible dans une NACL si configurée.'}"
            )

        logger.info(f"[RÉSULTAT] {resultat['message']}")
        return resultat

    except ClientError as e:
        code    = e.response["Error"]["Code"]
        message = e.response["Error"]["Message"]
        logger.error(f"[ERREUR AWS] {code}: {message}")
        resultat["statut"]  = "ERREUR"
        resultat["message"] = f"Erreur AWS {code}: {message}"
        return resultat

    except NoCredentialsError:
        msg = "Credentials AWS manquantes — configurez AWS_ACCESS_KEY_ID et AWS_SECRET_ACCESS_KEY dans .env"
        logger.error(f"[ERREUR] {msg}")
        resultat["statut"]  = "ERREUR_CREDENTIALS"
        resultat["message"] = msg
        return resultat

    except Exception as e:
        logger.error(f"[ERREUR INATTENDUE] {type(e).__name__}: {e}")
        resultat["statut"]  = "ERREUR"
        resultat["message"] = f"Erreur inattendue: {type(e).__name__}: {e}"
        return resultat


# ─── Fonction NACL ────────────────────────────────────────────────────────────
def _bloquer_ip_dans_nacl(ec2_client, ip_cidr: str, raison: str) -> dict:
    """
    Ajoute une règle DENY dans la Network ACL pour l'IP donnée.
    Les NACLs supportent les règles DENY explicites (contrairement aux SGs).

    Returns:
        dict avec statut et détails de la règle créée
    """
    try:
        # Récupérer les règles existantes de la NACL
        response = ec2_client.describe_network_acls(NetworkAclIds=[NACL_ID])
        nacl     = response["NetworkAcls"][0]
        entrees  = nacl.get("Entries", [])

        # Trouver un numéro de règle disponible (50, 51, 52, ...)
        numeros_existants = {e["RuleNumber"] for e in entrees if not e["Egress"]}
        numero_regle = NACL_RULE_NUMBER_START
        while numero_regle in numeros_existants:
            numero_regle += 1

        # Créer la règle DENY pour tout le trafic entrant depuis cette IP
        ec2_client.create_network_acl_entry(
            NetworkAclId=NACL_ID,
            RuleNumber=numero_regle,
            Protocol="-1",           # Tous les protocoles
            RuleAction="deny",        # DENY explicite
            Egress=False,             # Trafic entrant
            CidrBlock=ip_cidr,
            PortRange={"From": 0, "To": 65535}
        )

        logger.info(f"[NACL] Règle DENY #{numero_regle} créée pour {ip_cidr} dans {NACL_ID}")
        return {
            "statut":       "DENY_AJOUTÉ",
            "nacl_id":      NACL_ID,
            "rule_number":  numero_regle,
            "ip_cidr":      ip_cidr,
            "action":       "deny",
            "protocole":    "ALL",
            "message":      f"Règle DENY #{numero_regle} ajoutée dans NACL {NACL_ID}"
        }

    except ClientError as e:
        logger.warning(f"[NACL ERREUR] {e.response['Error']['Code']}: {e.response['Error']['Message']}")
        return {
            "statut":  "ERREUR",
            "message": f"NACL: {e.response['Error']['Code']} — {e.response['Error']['Message']}"
        }


# ─── Fonctions utilitaires ────────────────────────────────────────────────────
def debloquer_ip_secgroup(ip: str, security_group_id: Optional[str] = None) -> dict:
    """
    Retire le tag de blocage pour une IP (rollback / whitelist).
    Ne restaure pas les règles ALLOW supprimées (sécurité par défaut).

    Args:
        ip (str)               : IP à débloquer
        security_group_id (str): ID du SG cible

    Returns:
        dict avec statut du déblocage
    """
    ip_cidr = ip if "/" in ip else f"{ip}/32"
    sg_id   = security_group_id or SECURITY_GROUP_ID

    try:
        ec2 = _get_ec2_client()

        # Récupérer le tag actuel
        response_sg   = ec2.describe_security_groups(GroupIds=[sg_id])
        sg            = response_sg["SecurityGroups"][0]
        ips_bloquees  = []

        for tag in sg.get("Tags", []):
            if tag["Key"] == "IPs-Bloquees":
                try:
                    ips_bloquees = json.loads(tag["Value"])
                except Exception:
                    ips_bloquees = tag["Value"].split(",")
                break

        if ip_cidr in ips_bloquees:
            ips_bloquees.remove(ip_cidr)
            ec2.create_tags(
                Resources=[sg_id],
                Tags=[{"Key": "IPs-Bloquees", "Value": json.dumps(ips_bloquees)}]
            )
            logger.info(f"[DÉBLOCAGE] {ip_cidr} retirée de la liste de blocage")
            return {
                "statut":  "DÉBLOQUÉE",
                "ip":      ip,
                "message": f"IP {ip} retirée du tag 'IPs-Bloquees' de {sg_id}"
            }
        else:
            return {
                "statut":  "NON_TROUVÉE",
                "ip":      ip,
                "message": f"IP {ip} non trouvée dans la liste de blocage"
            }

    except Exception as e:
        return {
            "statut":  "ERREUR",
            "ip":      ip,
            "message": f"Erreur déblocage: {e}"
        }


def lister_ips_bloquees(security_group_id: Optional[str] = None) -> dict:
    """
    Liste toutes les IPs actuellement taguées comme bloquées dans le Security Group.

    Returns:
        dict avec liste des IPs bloquées et métadonnées
    """
    sg_id = security_group_id or SECURITY_GROUP_ID

    try:
        ec2 = _get_ec2_client()
        response_sg = ec2.describe_security_groups(GroupIds=[sg_id])
        sg          = response_sg["SecurityGroups"][0]

        ips_bloquees   = []
        dernier_blocage = None

        for tag in sg.get("Tags", []):
            if tag["Key"] == "IPs-Bloquees":
                try:
                    ips_bloquees = json.loads(tag["Value"])
                except Exception:
                    ips_bloquees = [t.strip() for t in tag["Value"].split(",") if t.strip()]
            elif tag["Key"] == "Dernier-Blocage":
                dernier_blocage = tag["Value"]

        return {
            "statut":          "OK",
            "security_group":  sg_id,
            "nb_ips_bloquees": len(ips_bloquees),
            "ips_bloquees":    ips_bloquees,
            "dernier_blocage": dernier_blocage,
            "regles_entree":   len(sg.get("IpPermissions", []))
        }

    except Exception as e:
        return {
            "statut":  "ERREUR",
            "message": str(e)
        }


def verifier_ip_bloquee(ip: str, security_group_id: Optional[str] = None) -> bool:
    """
    Vérifie si une IP est déjà dans la liste de blocage du Security Group.

    Args:
        ip (str)               : IP à vérifier
        security_group_id (str): ID du SG cible

    Returns:
        bool: True si bloquée, False sinon
    """
    ip_cidr = ip if "/" in ip else f"{ip}/32"
    liste   = lister_ips_bloquees(security_group_id)
    return ip_cidr in liste.get("ips_bloquees", [])


# ─── Intégration avec corrector_agent ─────────────────────────────────────────
def bloquer_depuis_anomalie(anomalie: dict) -> dict:
    """
    Interface directe pour le corrector_agent CrewAI.
    Prend un dict d'anomalie et déclenche le blocage approprié.

    Args:
        anomalie (dict): {
            "type": "BRUTE-FORCE SSH",
            "ip": "192.168.1.100",
            "severite": "CRITIQUE",
            ...
        }

    Returns:
        dict avec résultat du blocage
    """
    ip        = anomalie.get("ip", "")
    type_an   = anomalie.get("type", "").upper()
    severite  = anomalie.get("severite", "AVERTISSEMENT")

    if not ip or ip in ("N/A", "multiple", ""):
        return {
            "statut":  "IGNORÉ",
            "message": f"IP non spécifiée ou multiple — blocage manuel requis"
        }

    raison = (
        f"Agent IA CrewAI | Type: {type_an} | Sévérité: {severite} | "
        f"Timestamp: {datetime.now(timezone.utc).isoformat()}"
    )

    return bloquer_ip_secgroup(ip=ip, raison=raison)