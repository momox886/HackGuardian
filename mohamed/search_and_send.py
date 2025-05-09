import requests
from dotenv import load_dotenv
import os
import smtplib
from email.message import EmailMessage
import sys

load_dotenv()

def get_cves_by_vendor(vendor, page):
    url = f'https://app.opencve.io/api/cve?page={page}&vendor={vendor}'
    username = 'mopox06'
    password = os.getenv('PASSWORD')
    
    response = requests.get(url, auth=(username, password))
    if response.status_code == 200:
        return response.json().get('results', [])
    return []

def format_cve_email(cves, vendor):
    email_content = f"Rapport des CVEs pour le vendeur: {vendor}\n\n"
    email_content += "="*50 + "\n"
    
    for cve in cves:
        email_content += f"CVE ID: {cve.get('cve_id', 'N/A')}\n"
        email_content += f"Description: {cve.get('description', 'N/A')}\n"
        email_content += f"Date de création: {cve.get('created_at', 'N/A')}\n"
        email_content += f"Date de modification: {cve.get('updated_at', 'N/A')}\n"
        email_content += "="*50 + "\n"
    
    return email_content

def send_email(content, recipient):
    msg = EmailMessage()
    msg['Subject'] = 'Rapport des CVEs'
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
    if len(sys.argv) < 4:
        print("Usage: python search_and_send.py <vendor> <page> <email>")
        sys.exit(1)
        
    vendor = sys.argv[1]
    page = sys.argv[2]
    email = sys.argv[3]
    
    cves = get_cves_by_vendor(vendor, page)
    if cves:
        email_content = format_cve_email(cves, vendor)
        send_email(email_content, email)
    else:
        print(f"Aucune CVE trouvée pour le vendeur {vendor}")