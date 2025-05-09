import requests
from dotenv import load_dotenv
import os

# Permet d'utiliser des variables d'environnement pour y stocker des données sensibles
load_dotenv()

cve_id = input("Veuillez entrer l'identifiant de la CVE que vous voulez afficher : ")

# Authentification obligatoire pour pouvoir utiliser l'API
url = f'https://app.opencve.io/api/cve/{cve_id}'
password = os.getenv('PASSWORD')
username = 'mopox06'

response = requests.get(url, auth=(username, password))
def cve(response):
    if response.status_code == 200:
        print('Succès')
        try:
            data = response.json()

            # Extraction des champs principaux
            cve_ids = data.get('cve_id')
            title = data.get('title')
            description = data.get('description')
            date_creation = data.get('created_at')
            date_modif = data.get('updated_at')

            # CVSS v3.1
            cvss = data.get('metrics', {}).get('cvssV3_1', {}).get('data', {})
            score = cvss.get('score')
            vector = cvss.get('vector')

            # CVSS v3.0
            cvss0 = data.get('metrics', {}).get('cvssV3_0', {}).get('data', {})
            score0 = cvss0.get('score')
            vector0 = cvss0.get('vector')

            # Faiblesses CWE
            cwes = data.get('weaknesses', [])

            # Fournisseurs
            vendors = data.get('vendors', [])

            # Affichage
            print(f"CVE ID: {cve_ids}")
            print(f"Title: {title}")
            print(f"Description: {description}")
            print(f"Date de création: {date_creation}")
            print(f"Date de modification: {date_modif}")
            print(f"Score CVSS v3.1: {score if score else 'Non disponible'}")
            print(f"Vecteur CVSS v3.1: {vector if vector else 'Non disponible'}")
            print(f"Score CVSS v3.0: {score0 if score0 else 'Non disponible'}")
            print(f"Vecteur CVSS v3.0 {vector0 if vector0 else 'Non disponible'}")
            print("Faiblesses (CWE):", ", ".join(cwes) if cwes else "Non spécifiées")
            print("Fournisseurs:", ", ".join(vendors) if vendors else "Non spécifiés")

        except ValueError:
            print("Erreur : impossibilité de décoder la réponse JSON")
    else:
        print('Erreur', response.status_code)
cve(response)