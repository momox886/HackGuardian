from sqlalchemy import create_engine, text

# Connexion à la base PostgreSQL
username = 'opencve'
password = 'opencve'
host = '172.18.0.4'
port = '5432'
database = 'opencve'

# URL de connexion
db_url = f'postgresql://{username}:{password}@{host}:{port}/{database}'
engine = create_engine(db_url)

# Requête pour récupérer les CVE
query = """
SELECT id, cve_id, created_at
FROM opencve_cves
ORDER BY created_at DESC
LIMIT 20;
"""

# Exécution de la requête
with engine.connect() as conn:
    result = conn.execute(text(query))
    cves = result.fetchall()

# Affichage des CVE
print("🛡️  Derniers CVE :")
for cve in cves:
    print(f"- {cve.cve_id} | (créé le {cve.created_at})")

