"""
agents_patch_aws.py
Patch à appliquer dans agents.py pour que OutilActionCorrective
appelle RÉELLEMENT bloquer_ip_secgroup() via Boto3.

Remplacez la méthode _run() de OutilActionCorrective dans agents.py
par la version ci-dessous, ou importez ce module après agents.py.

Ajout à faire dans agents.py (en haut, après les imports existants) :
    from src.aws_security import bloquer_ip_secgroup, bloquer_depuis_anomalie
"""

# ── Patch OutilActionCorrective._run() ────────────────────────────────────────
# Collez ce bloc dans la méthode _run() de OutilActionCorrective dans agents.py
# après la ligne : result_str = json.dumps(action, ...)

PATCH_INTEGRATION = """
# ── INTÉGRATION AWS RÉELLE — ajout dans OutilActionCorrective._run() ──────────

# Import au début du fichier agents.py :
try:
    from src.aws_security import bloquer_ip_secgroup, bloquer_depuis_anomalie
    AWS_SECURITY_DISPONIBLE = True
except ImportError:
    AWS_SECURITY_DISPONIBLE = False
    print("[WARN] aws_security non disponible — mode simulation uniquement")

# Dans _run(), AVANT le return, ajoutez :

if AWS_SECURITY_DISPONIBLE and ("BRUTE" in type_anomalie.upper() or "SSH" in type_anomalie.upper()):
    if ip and ip not in ("N/A", "multiple", ""):
        print(f"[AWS] Blocage RÉEL de {ip} via Boto3...")
        aws_result = bloquer_ip_secgroup(
            ip=ip,
            raison=f"Agent IA CrewAI | {type_anomalie} | Sévérité: {severite}"
        )
        action["aws_blocage_reel"] = aws_result
        action["aws_statut"]       = aws_result.get("statut", "INCONNU")
        print(f"[AWS] Résultat: {aws_result.get('message', 'N/A')}")
    else:
        action["aws_blocage_reel"] = {"statut": "IGNORÉ", "raison": f"IP={ip} non spécifique"}
"""

if __name__ == "__main__":
    print("Ce fichier est un guide de patch — voir agents_patch_aws.py")
    print(PATCH_INTEGRATION)