import requests
from dotenv import load_dotenv
import os

load_dotenv()

username = 'mopox06'
password = os.getenv('PASSWORD')


page = input("Veuillez entrez la page de recherche: ")
url = f'https://app.opencve.io/api/vendors?page={page}'

response = requests.get(url , auth=(username , password))

if response.status_code == 200:
    print('Sucées')
    try:
        data = response.json()
        if 'results' in data:
             for item in data['results']:
                id = item.get('id')
                name = item.get('name')
                date = item.get ('created_at')
            
                print(f"Vendors name: {name}")
                print(f"Id: {id}")
                print(f"Date de création : {date}")
                print("--------------------")

        else:
            # Si la structure ne contient pas 'results', affichez la structure pour debug
            print("Structure JSON inattendue :")
            print(data)
    except ValueError:
         print("Erreur : impossibilité de décoder la réponse JSON")
else:
    print ('Erreur', response.status_code)
