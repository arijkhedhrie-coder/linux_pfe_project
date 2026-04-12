import boto3
import pandas as pd
import chromadb
import hashlib
import io
import os
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# =============================================
# CONFIGURATION
# =============================================
BUCKET_NAME    = "pfe-linux-logs-supervision"
AWS_REGION     = "us-east-1"
AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")

CHROMA_DB_PATH = "./chroma_db"
COLLECTION_NAME = "logs_attaques"

# =============================================
# CONNEXION AWS S3
# =============================================
def connecter_s3():
    print("[S3] Connexion à AWS S3...")
    client = boto3.client(
        "s3",
        region_name=AWS_REGION,
        aws_access_key_id=AWS_ACCESS_KEY,
        aws_secret_access_key=AWS_SECRET_KEY
    )
    print("[S3] ✅ Connecté")
    return client

# =============================================
# LIRE LES CSV DEPUIS S3
# =============================================
def lire_csv_depuis_s3(s3_client):
    print("\n[S3] Récupération des fichiers CSV...")
    fichiers_cibles = [
        "processed/dataset_",
        "processed/latest_logs.csv",
        "processed/stats_logs.csv"
    ]

    dataframes = []
    response = s3_client.list_objects_v2(Bucket=BUCKET_NAME, Prefix="processed/")

    if "Contents" not in response:
        print("[S3] ⚠️ Aucun fichier trouvé dans processed/")
        return pd.DataFrame()

    for obj in response["Contents"]:
        key = obj["Key"]
        if not key.endswith(".csv"):
            continue

        # Prendre seulement dataset_ et latest_logs
        if "dataset_" in key or "latest_logs" in key:
            try:
                print(f"[S3] 📥 Téléchargement : {key}")
                csv_obj = s3_client.get_object(Bucket=BUCKET_NAME, Key=key)
                df = pd.read_csv(io.BytesIO(csv_obj["Body"].read()))
                dataframes.append(df)
                print(f"[S3] ✅ {len(df)} lignes chargées depuis {key}")
            except Exception as e:
                print(f"[S3] ❌ Erreur sur {key} : {e}")

    if not dataframes:
        print("[S3] ⚠️ Aucun DataFrame chargé")
        return pd.DataFrame()

    df_total = pd.concat(dataframes, ignore_index=True)
    df_total = df_total.drop_duplicates()
    print(f"\n[S3] ✅ Total : {len(df_total)} événements uniques chargés")
    return df_total

# =============================================
# CONVERTIR UNE LIGNE EN TEXTE POUR EMBEDDING
# =============================================
def ligne_vers_texte(row: dict) -> str:
    parties = []
    champs_importants = [
        "event_type", "source_ip", "username", "action",
        "status", "message", "log_source", "timestamp"
    ]
    for champ in champs_importants:
        valeur = row.get(champ, "")
        if valeur and str(valeur).strip() not in ["", "nan", "None"]:
            parties.append(f"{champ}: {valeur}")

    # Ajouter les autres champs disponibles
    for k, v in row.items():
        if k not in champs_importants and str(v).strip() not in ["", "nan", "None"]:
            parties.append(f"{k}: {v}")

    return " | ".join(parties)

# =============================================
# PEUPLER CHROMADB
# =============================================
def peupler_chromadb(df: pd.DataFrame):
    if df.empty:
        print("[ChromaDB] ❌ DataFrame vide, rien à insérer")
        return

    print(f"\n[ChromaDB] Initialisation de la base vectorielle...")
    client = chromadb.PersistentClient(path=CHROMA_DB_PATH)

    # Supprimer et recréer la collection pour éviter les doublons
    try:
        client.delete_collection(COLLECTION_NAME)
        print(f"[ChromaDB] 🗑️ Ancienne collection supprimée")
    except:
        pass

    collection = client.create_collection(
        name=COLLECTION_NAME,
        metadata={"description": "Logs d'attaques Linux pour détection d'anomalies"}
    )
    print(f"[ChromaDB] ✅ Collection '{COLLECTION_NAME}' créée")

    # Préparer les données par batch de 100
    BATCH_SIZE = 100
    total = len(df)
    inseres = 0

    print(f"\n[ChromaDB] Insertion de {total} événements...")

    for i in range(0, total, BATCH_SIZE):
        batch = df.iloc[i:i+BATCH_SIZE]
        documents = []
        ids = []
        metadatas = []

        for _, row in batch.iterrows():
            row_dict = row.to_dict()
            texte = ligne_vers_texte(row_dict)

            # Générer un ID unique basé sur le contenu
            doc_id = hashlib.md5(texte.encode()).hexdigest()

            # Métadonnées pour filtrage
            metadata = {
                "event_type": str(row_dict.get("event_type", "UNKNOWN")),
                "source_ip":  str(row_dict.get("source_ip", "")),
                "log_source": str(row_dict.get("log_source", "")),
                "timestamp":  str(row_dict.get("timestamp", "")),
                "status":     str(row_dict.get("status", "")),
            }

            documents.append(texte)
            ids.append(doc_id)
            metadatas.append(metadata)

        # Dédupliquer les IDs dans le batch
        seen = set()
        docs_uniques, ids_uniques, metas_uniques = [], [], []
        for doc, did, meta in zip(documents, ids, metadatas):
            if did not in seen:
                seen.add(did)
                docs_uniques.append(doc)
                ids_uniques.append(did)
                metas_uniques.append(meta)

        try:
            collection.add(
                documents=docs_uniques,
                ids=ids_uniques,
                metadatas=metas_uniques
            )
            inseres += len(ids_uniques)
            print(f"[ChromaDB] Batch {i//BATCH_SIZE + 1} : {inseres}/{total} insérés", end="\r")
        except Exception as e:
            print(f"\n[ChromaDB] ❌ Erreur batch {i} : {e}")

    print(f"\n[ChromaDB] ✅ {inseres} événements insérés dans ChromaDB")
    return collection

# =============================================
# TEST DE RECHERCHE RAG
# =============================================
def tester_recherche(collection):
    print("\n[TEST RAG] Test de recherche dans ChromaDB...")
    requetes_test = [
        "SSH brute force attack failed login",
        "Nmap port scan reconnaissance",
        "Hydra credential stuffing"
    ]

    for requete in requetes_test:
        resultats = collection.query(
            query_texts=[requete],
            n_results=3
        )
        print(f"\n🔍 Requête : '{requete}'")
        for j, doc in enumerate(resultats["documents"][0]):
            print(f"  [{j+1}] {doc[:120]}...")

# =============================================
# FONCTION PRINCIPALE
# =============================================
def main():
    print("=" * 60)
    print("  POPULATION CHROMADB — MÉMOIRE RAG")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    # 1. Connexion S3
    s3_client = connecter_s3()

    # 2. Charger les CSV depuis S3
    df = lire_csv_depuis_s3(s3_client)

    if df.empty:
        print("\n Aucune donnée à insérer. Vérifiez S3.")
        return

    # 3. Peupler ChromaDB
    collection = peupler_chromadb(df)

    # 4. Test de recherche
    if collection:
        tester_recherche(collection)

    print("\n" + "=" * 60)
    print(" CHROMADB PEUPLÉ AVEC SUCCÈS !")
    print(f" Base stockée dans : {CHROMA_DB_PATH}")
    print("=" * 60)

if __name__ == "__main__":
    main()