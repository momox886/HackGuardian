import requests
from dotenv import load_dotenv
import os

# Permet d'utiliser des variables d'environement pour y stocker des données sensibles
load_dotenv()

# Autentifivation obligatoire pour pouvoir utiliser l'api
url = 'https://app.opencve.io/api/cve?vendor=python'
password = os.getenv('PASSWORD')
username = 'mopox06'

response = requests.get(url, auth=(username, password))


if response.status_code == 200:
    print ('Succés')
    try:
        data = response.json()
        if 'results' in data:
             for item in data['results']:
                    # accéder à un champ spécifique de l'item
                    # accées au info complet des cve pour le venders microsoft
                    cve_id = item.get('cve_id')
                    description = item.get('description')
                    date_creation = item.get('created_at')
                    date_modif = item.get('updated_at')
                    print(f"CVE ID: {cve_id}")
                    print(f"Description: {description}")
                    print(f"Date de création: {date_creation}")
                    print(f"Date de modification: {date_modif}")
                    print('---')
        else:
            # Si la structure ne contient pas 'results', affichez la structure pour debug
            print("Structure JSON inattendue :")
            print(data)
    except ValueError:
         print("Erreur : impossibilité de décoder la réponse JSON")
else:
    print ('Erreur', response.status_code)