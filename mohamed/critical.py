import requests
import os
from requests.auth import HTTPBasicAuth
from dotenv import load_dotenv

load_dotenv()

url = "https://app.opencve.io/api/cve"
params = {"cvss": "critical"}
password = os.getenv('PASSWORD')
auth = HTTPBasicAuth("mopox06", password=password)
response = requests.get(url, params=params, auth=auth)



if response.status_code == 200:
    print('succés')
    try:
        data = response.json()
        if 'results' in data:
                for item in data['results']:
                    id = item.get('cve_id')
                    descript = item.get('description')
                    date = item.get ('created_at')
                    modif = item.get ('updated_at')
                
                    print(f"Cve id: {id}")
                    print(f"Date de création : {date}")
                    print(f"Date de modif: {modif}")
                    print(f"Description: {descript}")
                    print("--------------------")

        else:
                # Si la structure ne contient pas 'results', affichez la structure pour debug
                print("Structure JSON inattendue :")
                print(data)
    except ValueError:
            print("Erreur : impossibilité de décoder la réponse JSON")
    
else:
        print ('Erreur', response.status_code)


