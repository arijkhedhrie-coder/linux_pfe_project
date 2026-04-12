import boto3
from dotenv import load_dotenv
import os

load_dotenv()

# Connexion AWS S3
s3_client = boto3.client(
    "s3",
    aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
    region_name=os.getenv("AWS_REGION", "us-east-1"),
)

BUCKET_NAME = os.getenv("S3_BUCKET_NAME", "pfe-linux-logs-supervision")


def list_objects(prefix: str = "") -> list:
    """Liste tous les objets dans le bucket S3.

    Retourne une liste de cles (chemins d'objets).
    """
    try:
        response = s3_client.list_objects_v2(Bucket=BUCKET_NAME, Prefix=prefix)
        objects = [obj["Key"] for obj in response.get("Contents", [])]
        return objects
    except Exception as exc:
        raise Exception(f"S3 list error: {exc}")


def read_object(key: str) -> str:
    """Lit le contenu d'un objet S3.

    Retourne le contenu sous forme de chaine.
    """
    try:
        response = s3_client.get_object(Bucket=BUCKET_NAME, Key=key)
        content = response["Body"].read().decode("utf-8", errors="ignore")
        return content
    except Exception as exc:
        raise Exception(f"S3 read error: {exc}")


def save_report(content: str, key: str) -> str:
    """Enregistre un rapport (ou tout contenu texte) dans S3.

    Retourne un message de confirmation.
    """
    try:
        s3_client.put_object(
            Bucket=BUCKET_NAME,
            Key=key,
            Body=content.encode("utf-8"),
            ContentType="text/plain",
        )
        return f"Saved to s3://{BUCKET_NAME}/{key}"
    except Exception as exc:
        raise Exception(f"S3 save error: {exc}")
