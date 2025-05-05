import requests
from bs4 import BeautifulSoup


# URL de la page à récupérer
url = "http://localhost:80/cve/?weakness=CWE-119"

try:
    # Envoi de la requête GET
    response = requests.get(url)

    # Vérification si la requête est OK
    if response.status_code == 200:
        print("✅ Requête réussie !")
        # Afficher le contenu de la réponse (HTML brut)
    else:
        print(f"❌ Erreur {response.status_code} lors de la requête.")

except requests.exceptions.RequestException as e:
    print(f"⚠️ Une erreur est survenue : {e}")



try:
    # Récupération de la page
    response = requests.get(url)
    response.raise_for_status()  # lève une erreur si le serveur répond mal

    # Parsing du contenu HTML
    soup = BeautifulSoup(response.text, 'html.parser')

    # Supposons que les CVE sont dans des balises spécifiques
    # (par exemple, des balises <a> ou <div> avec une classe particulière)
    cve_entries = soup.find_all('a', href=True)

    print("📋 Liste des CVEs trouvées :\n")

    for entry in cve_entries:
        href = entry['href']
        if href.startswith("/cve/"):  # généralement OpenCVE liste comme ça
            print(f"- {entry.text.strip()} (lien : http://localhost:80{href})")

except requests.exceptions.RequestException as e:
    print(f"⚠️ Une erreur est survenue : {e}")
