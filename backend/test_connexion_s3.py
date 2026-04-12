import boto3

# Vérifier la configuration actuelle
session = boto3.Session()
print(f"Région configurée: {session.region_name}")
print(f"Credentials disponibles: {session.get_credentials() is not None}")

# Lister les buckets existants (pour tester la connexion)
try:
    s3 = boto3.client('s3')
    s3.create_bucket(Bucket='123-logs-supervision-bucket')
    response = s3.list_buckets()
    print("Connexion réussie!")
    print("Buckets existants:")
    for bucket in response['Buckets']:
        print(f"  {bucket['Name']}")
except Exception as e:
    print(f"Erreur de connexion: {e}")