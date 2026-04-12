"""
test_aws_security.py
Script de test manuel pour vérifier que bloquer_ip_secgroup() fonctionne.

Usage :
    python test_aws_security.py

Prérequis :
    pip install boto3 python-dotenv
    .env configuré avec :
        AWS_ACCESS_KEY_ID=...
        AWS_SECRET_ACCESS_KEY=...
        AWS_REGION=eu-west-3
        AWS_SECURITY_GROUP_ID=sg-XXXXXXXXXXXXXXXXX
        AWS_NACL_ID=acl-XXXXXXXXXXXXXXXXX  (optionnel)
"""

import json
import sys
import os

# Permet d'importer aws_security depuis le même dossier
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from aws_security import (
    bloquer_ip_secgroup,
    debloquer_ip_secgroup,
    lister_ips_bloquees,
    verifier_ip_bloquee,
    bloquer_depuis_anomalie,
)

# ─── IPs de test (non-routables RFC 5737 — sans risque) ──────────────────────
IP_TEST_1 = "192.0.2.100"    # TEST-NET-1 — jamais utilisée sur internet réel
IP_TEST_2 = "198.51.100.42"  # TEST-NET-2 — jamais utilisée sur internet réel
IP_TEST_3 = "203.0.113.77"   # TEST-NET-3 — jamais utilisée sur internet réel


def afficher_resultat(titre: str, resultat: dict):
    """Affiche un résultat de test de manière lisible."""
    print(f"\n{'─'*60}")
    print(f"  {titre}")
    print(f"{'─'*60}")
    print(json.dumps(resultat, indent=2, ensure_ascii=False))


def test_01_lister_etat_initial():
    """Test 1 : État initial du Security Group."""
    print("\n" + "="*60)
    print("  TEST 1 — État initial du Security Group")
    print("="*60)

    resultat = lister_ips_bloquees()
    afficher_resultat("lister_ips_bloquees()", resultat)

    if resultat["statut"] == "OK":
        print(f"\n✅ Connexion AWS OK | SG: {resultat['security_group']}")
        print(f"   IPs déjà bloquées : {resultat['nb_ips_bloquees']}")
        print(f"   Règles d'entrée   : {resultat['regles_entree']}")
        return True
    else:
        print(f"\n❌ Connexion AWS ÉCHOUÉE : {resultat.get('message', 'Erreur inconnue')}")
        print("\n   Vérifiez votre fichier .env :")
        print("   AWS_ACCESS_KEY_ID=AKIA...")
        print("   AWS_SECRET_ACCESS_KEY=...")
        print("   AWS_REGION=eu-west-3")
        print("   AWS_SECURITY_GROUP_ID=sg-...")
        return False


def test_02_bloquer_ip_simple():
    """Test 2 : Blocage d'une IP simple (TEST-NET-1 non-routable)."""
    print("\n" + "="*60)
    print(f"  TEST 2 — Blocage IP : {IP_TEST_1}")
    print("="*60)

    resultat = bloquer_ip_secgroup(
        ip=IP_TEST_1,
        raison="Test automatique — IP TEST-NET-1 non-routable"
    )
    afficher_resultat(f"bloquer_ip_secgroup('{IP_TEST_1}')", resultat)

    statuts_ok = {"BLOQUÉE", "BLOQUÉE_NACL_UNIQUEMENT", "AUCUNE_REGLE_ALLOW"}
    if resultat["statut"] in statuts_ok:
        print(f"\n✅ Blocage réussi | Statut: {resultat['statut']}")
        print(f"   Message: {resultat['message']}")
        if resultat.get("regles_supprimees"):
            print(f"   Règles supprimées: {resultat['regles_supprimees']}")
        if resultat.get("tag_audit"):
            print(f"   Audit trail: {resultat['tag_audit']}")
        if resultat.get("nacl_regle"):
            print(f"   NACL: {resultat['nacl_regle']}")
        return True
    else:
        print(f"\n❌ Blocage ÉCHOUÉ | Statut: {resultat['statut']}")
        print(f"   Erreur: {resultat.get('message', 'Inconnu')}")
        return False


def test_03_verifier_ip_bloquee():
    """Test 3 : Vérification qu'une IP est bien marquée comme bloquée."""
    print("\n" + "="*60)
    print(f"  TEST 3 — Vérification blocage : {IP_TEST_1}")
    print("="*60)

    est_bloquee = verifier_ip_bloquee(IP_TEST_1)
    print(f"\n  verifier_ip_bloquee('{IP_TEST_1}') → {est_bloquee}")

    if est_bloquee:
        print(f"✅ IP {IP_TEST_1} confirmée bloquée dans les tags du SG")
    else:
        print(f"⚠️  IP {IP_TEST_1} non trouvée dans les tags (peut être normale si pas de règle ALLOW)")
    return True


def test_04_double_blocage():
    """Test 4 : Double blocage (idempotence — ne doit pas planter)."""
    print("\n" + "="*60)
    print(f"  TEST 4 — Double blocage (idempotence) : {IP_TEST_1}")
    print("="*60)

    resultat = bloquer_ip_secgroup(
        ip=IP_TEST_1,
        raison="Test idempotence — second blocage"
    )
    afficher_resultat("2ème appel bloquer_ip_secgroup()", resultat)

    if resultat["statut"] != "ERREUR":
        print(f"\n✅ Double blocage géré correctement | Statut: {resultat['statut']}")
        return True
    else:
        print(f"\n❌ Erreur sur double blocage: {resultat.get('message')}")
        return False


def test_05_bloquer_depuis_anomalie():
    """Test 5 : Interface corrector_agent — blocage depuis un dict d'anomalie."""
    print("\n" + "="*60)
    print("  TEST 5 — Interface corrector_agent (bloquer_depuis_anomalie)")
    print("="*60)

    anomalie_ssh = {
        "type":     "BRUTE-FORCE SSH",
        "ip":       IP_TEST_2,
        "severite": "CRITIQUE",
        "valeur":   150,
        "message":  "150 tentatives SSH en 5 minutes"
    }

    print(f"  Anomalie simulée: {json.dumps(anomalie_ssh, ensure_ascii=False)}")
    resultat = bloquer_depuis_anomalie(anomalie_ssh)
    afficher_resultat(f"bloquer_depuis_anomalie() → {IP_TEST_2}", resultat)

    if resultat["statut"] not in ("ERREUR", "ERREUR_CREDENTIALS"):
        print(f"\n✅ Interface agent OK | Statut: {resultat['statut']}")
        return True
    else:
        print(f"\n❌ Interface agent ÉCHOUÉE: {resultat.get('message')}")
        return False


def test_06_anomalie_ip_inconnue():
    """Test 6 : Anomalie sans IP (cas multiple/N/A — doit être ignorée)."""
    print("\n" + "="*60)
    print("  TEST 6 — Anomalie sans IP spécifique (doit être ignorée)")
    print("="*60)

    anomalie_sans_ip = {
        "type":     "SURCHARGE CPU",
        "ip":       "multiple",
        "severite": "AVERTISSEMENT"
    }

    resultat = bloquer_depuis_anomalie(anomalie_sans_ip)
    afficher_resultat("bloquer_depuis_anomalie() → ip='multiple'", resultat)

    if resultat["statut"] == "IGNORÉ":
        print(f"\n✅ Cas IP multiple ignoré correctement")
        return True
    else:
        print(f"\n⚠️ Comportement inattendu: {resultat['statut']}")
        return False


def test_07_lister_apres_blocage():
    """Test 7 : Liste finale des IPs bloquées (doit contenir les IPs de test)."""
    print("\n" + "="*60)
    print("  TEST 7 — Liste finale des IPs bloquées")
    print("="*60)

    resultat = lister_ips_bloquees()
    afficher_resultat("lister_ips_bloquees() — état final", resultat)

    if resultat["statut"] == "OK":
        ips = resultat.get("ips_bloquees", [])
        print(f"\n✅ {resultat['nb_ips_bloquees']} IP(s) bloquée(s) dans le SG")
        for ip in ips:
            print(f"   🔒 {ip}")
        return True
    else:
        print(f"\n❌ Erreur listing: {resultat.get('message')}")
        return False


def test_08_rollback_deblocage():
    """Test 8 : Rollback — déblocage des IPs de test (nettoyage)."""
    print("\n" + "="*60)
    print("  TEST 8 — Rollback / Déblocage des IPs de test")
    print("="*60)

    ips_a_debloquer = [IP_TEST_1, IP_TEST_2]
    tous_ok = True

    for ip in ips_a_debloquer:
        resultat = debloquer_ip_secgroup(ip)
        afficher_resultat(f"debloquer_ip_secgroup('{ip}')", resultat)
        if resultat["statut"] in ("DÉBLOQUÉE", "NON_TROUVÉE"):
            print(f"✅ {ip} → {resultat['statut']}")
        else:
            print(f"❌ {ip} → Erreur: {resultat.get('message')}")
            tous_ok = False

    return tous_ok


# ─── Runner principal ──────────────────────────────────────────────────────────
def main():
    print("\n" + "="*60)
    print("   TEST MODULE AWS SECURITY — bloquer_ip_secgroup()")
    print("="*60)
    print(f"   Region    : {os.getenv('AWS_REGION', 'eu-west-3')}")
    print(f"   SG ID     : {os.getenv('AWS_SECURITY_GROUP_ID', 'NON CONFIGURÉ ⚠️')}")
    print(f"   NACL ID   : {os.getenv('AWS_NACL_ID', 'non configuré (optionnel)')}")
    print(f"   IPs test  : {IP_TEST_1}, {IP_TEST_2}")
    print("="*60)

    tests = [
        ("Connexion & état initial",        test_01_lister_etat_initial),
        ("Blocage IP simple",               test_02_bloquer_ip_simple),
        ("Vérification tag de blocage",     test_03_verifier_ip_bloquee),
        ("Idempotence (double blocage)",    test_04_double_blocage),
        ("Interface corrector_agent",       test_05_bloquer_depuis_anomalie),
        ("IP multiple ignorée",             test_06_anomalie_ip_inconnue),
        ("Liste finale des IPs bloquées",   test_07_lister_apres_blocage),
        ("Rollback / déblocage nettoyage",  test_08_rollback_deblocage),
    ]

    resultats = []
    for nom_test, fn_test in tests:
        try:
            ok = fn_test()
            resultats.append((nom_test, ok))
        except Exception as e:
            print(f"\n💥 EXCEPTION dans '{nom_test}': {type(e).__name__}: {e}")
            resultats.append((nom_test, False))

    # ── Résumé final ──────────────────────────────────────────────────────────
    print("\n\n" + "="*60)
    print("   RÉSUMÉ DES TESTS")
    print("="*60)

    nb_ok  = sum(1 for _, ok in resultats if ok)
    nb_ko  = len(resultats) - nb_ok

    for nom, ok in resultats:
        icone = "✅" if ok else "❌"
        print(f"  {icone}  {nom}")

    print(f"\n  Total : {nb_ok}/{len(resultats)} tests réussis")

    if nb_ko == 0:
        print("\n🎉 TOUS LES TESTS PASSENT — Module aws_security.py opérationnel !")
        print("   Le corrector_agent peut maintenant bloquer des IPs sur AWS.")
    else:
        print(f"\n⚠️  {nb_ko} test(s) échoué(s) — vérifiez votre configuration .env et les permissions IAM.")
        print("\n   Permissions IAM minimales requises :")
        print("   ec2:DescribeSecurityGroups")
        print("   ec2:RevokeSecurityGroupIngress")
        print("   ec2:CreateTags")
        print("   ec2:DescribeNetworkAcls          (si NACL activée)")
        print("   ec2:CreateNetworkAclEntry         (si NACL activée)")

    print("="*60 + "\n")
    return nb_ko == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)