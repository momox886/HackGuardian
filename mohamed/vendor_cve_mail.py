import requests
from dotenv import load_dotenv
import os
import smtplib
from email.message import EmailMessage
from datetime import datetime

load_dotenv()

def get_cve_details(cve_id):
    """Récupère les détails complets d'une CVE"""
    url = f'https://app.opencve.io/api/cve/{cve_id}'
    username = 'mopox06'
    password = os.getenv('PASSWORD')
    
    try:
        response = requests.get(url, auth=(username, password), timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Erreur lors de la récupération de la CVE {cve_id}: {e}")
        return None

def get_cves_by_vendor(vendor, page=1):
    """Récupère les CVEs pour un vendeur spécifique"""
    url = f'https://app.opencve.io/api/cve?page={page}&vendor={vendor}'
    username = 'mopox06'
    password = os.getenv('PASSWORD')
    
    try:
        response = requests.get(url, auth=(username, password), timeout=10)
        response.raise_for_status()
        return response.json().get('results', [])
    except requests.exceptions.RequestException as e:
        print(f"Erreur lors de la récupération des CVEs: {e}")
        return []

def format_cve_details(cve_data):
    """Formate les détails complets d'une CVE"""
    if not cve_data:
        return "Aucune information disponible pour cette CVE\n"
    
    details = f"\n{'='*80}\n"
    details += f"CVE ID: {cve_data.get('cve_id', 'N/A')}\n"
    details += f"Titre: {cve_data.get('title', 'N/A')}\n"
    details += f"Description: {cve_data.get('description', 'N/A')}\n"
    details += f"Date création: {cve_data.get('created_at', 'N/A')}\n"
    details += f"Date modification: {cve_data.get('updated_at', 'N/A')}\n\n"

    # Détails CVSS
    for version in ['cvssV3_1', 'cvssV3_0']:
        cvss_data = cve_data.get('metrics', {}).get(version, {}).get('data', {})
        if cvss_data:
            details += f"CVSS {version.replace('cvssV', 'v')}:\n"
            details += f"- Score: {cvss_data.get('score', 'N/A')}\n"
            details += f"- Vecteur: {cvss_data.get('vector', 'N/A')}\n"
            if version == 'cvssV3_1':
                details += f"- Severité: {cvss_data.get('severity', 'N/A')}\n"
            details += "\n"

    # Faiblesses (CWE)
    cwes = cve_data.get('weaknesses', [])
    details += "Faiblesses (CWE):\n"
    if cwes:
        for cwe in cwes:
            details += f"- {cwe}\n"
    else:
        details += "- Non spécifiées\n"
    details += "\n"

    # Produits affectés
    vendors = cve_data.get('vendors', [])
    details += "Produits affectés:\n"
    if isinstance(vendors, dict):
        for vendor, products in vendors.items():
            details += f"- Vendeur: {vendor}\n"
            for product in products:
                details += f"  - {product}\n"
    elif isinstance(vendors, list):
        for vendor in vendors:
            details += f"- Vendeur: {vendor}\n"
    else:
        details += "- Non spécifiés\n"

    details += f"\n{'='*80}\n"
    return details

def send_cve_report(vendor, recipient, page=1):
    """Envoie le rapport complet des CVEs par email"""
    cves = get_cves_by_vendor(vendor, page)
    
    if not cves:
        print(f"Aucune CVE trouvée pour le vendeur {vendor}")
        return False

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    email_content = f"Rapport complet des CVEs pour le vendeur: {vendor}\n"
    email_content += f"Page: {page} | Généré le: {now}\n\n"
    email_content += f"Nombre de CVEs trouvées: {len(cves)}\n\n"

    for cve in cves:
        cve_id = cve.get('cve_id')
        if cve_id:
            cve_details = get_cve_details(cve_id)
            email_content += format_cve_details(cve_details)

    msg = EmailMessage()
    msg['Subject'] = f'Rapport CVEs complet - {vendor} (Page {page})'
    msg['From'] = os.getenv('EMAIL_FROM', 'habibdiallo2306@gmail.com')
    msg['To'] = recipient
    msg.set_content(email_content)

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(msg['From'], os.getenv('MDP'))
            smtp.send_message(msg)
            print(f"Email envoyé avec succès à {recipient}")
            return True
    except Exception as e:
        print(f"Erreur lors de l'envoi du mail : {e}")
        return False

if __name__ == "__main__":
    print("=== Envoi des CVEs par email ===")
    vendor = input("Entrez le nom du vendeur: ").strip()
    page = input("Entrez le numéro de page (1 par défaut): ").strip() or "1"
    recipient = input("Entrez l'email destinataire: ").strip()
    
    send_cve_report(vendor, recipient, page)