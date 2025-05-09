import requests
from dotenv import load_dotenv
import os
import smtplib
from email.message import EmailMessage

load_dotenv()

def get_cve_details(cve_id):
    url = f'https://app.opencve.io/api/cve/{cve_id}'
    password = os.getenv('PASSWORD')
    username = 'mopox06'
    
    response = requests.get(url, auth=(username, password))
    if response.status_code == 200:
        return response.json()
    return None

def format_cve_details(data):
    if not data:
        return "Aucune information disponible pour cette CVE"
    
    formatted = f"CVE ID: {data.get('cve_id', 'N/A')}\n"
    formatted += f"Title: {data.get('title', 'N/A')}\n"
    formatted += f"Description: {data.get('description', 'N/A')}\n"
    formatted += f"Date de création: {data.get('created_at', 'N/A')}\n"
    formatted += f"Date de modification: {data.get('updated_at', 'N/A')}\n"
    
    cvss = data.get('metrics', {}).get('cvssV3_1', {}).get('data', {})
    formatted += f"Score CVSS v3.1: {cvss.get('score', 'Non disponible')}\n"
    formatted += f"Vecteur CVSS v3.1: {cvss.get('vector', 'Non disponible')}\n"
    
    cvss0 = data.get('metrics', {}).get('cvssV3_0', {}).get('data', {})
    formatted += f"Score CVSS v3.0: {cvss0.get('score', 'Non disponible')}\n"
    formatted += f"Vecteur CVSS v3.0: {cvss0.get('vector', 'Non disponible')}\n"
    
    cwes = data.get('weaknesses', [])
    formatted += f"Faiblesses (CWE): {', '.join(cwes) if cwes else 'Non spécifiées'}\n"
    
    vendors = data.get('vendors', [])
    formatted += f"Fournisseurs: {', '.join(vendors) if vendors else 'Non spécifiés'}\n"
    
    return formatted

def send_email(content, recipient):
    msg = EmailMessage()
    msg['Subject'] = 'Détails de la CVE'
    msg['From'] = 'habibdiallo2306@gmail.com'
    msg['To'] = recipient
    msg.set_content(content)
    
    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login('habibdiallo2306@gmail.com', os.getenv('MDP'))
            smtp.send_message(msg)
            print("Email envoyé avec succès !")
    except Exception as e:
        print(f"Erreur lors de l'envoi du mail : {e}")

if __name__ == "__main__":
    cve_id = input("Veuillez entrer l'identifiant de la CVE que vous voulez afficher : ")
    data = get_cve_details(cve_id)
    
    if data:
        formatted = format_cve_details(data)
        print(formatted)
        
        send_option = input("Voulez-vous envoyer ces informations par email ? (o/n): ")
        if send_option.lower() == 'o':
            recipient = input("Entrez l'email destinataire: ")
            send_email(formatted, recipient)
    else:
        print("Erreur: Impossible de récupérer les détails de la CVE")