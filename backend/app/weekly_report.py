from flask import current_app
from .models import Vulnerability, Subscriber
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText
import os
from dotenv import load_dotenv
from sqlalchemy import func

load_dotenv()

# Chargement des infos d'envoi SMTP
EMAIL_SENDER = os.getenv('EMAIL_SENDER')
EMAIL_PASSWORD = os.getenv('MDP')
SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.getenv('SMTP_PORT', 465))  # SSL par défaut


def get_weekly_cves_for_vendors(vendor_list):
    """
    Récupère les vulnérabilités ajoutées cette semaine pour les vendeurs abonnés.
    """
    if not vendor_list:
        return []

    now = datetime.utcnow()
    week_ago = now - timedelta(days=7)

    normalized_vendors = [v.strip().lower() for v in vendor_list]

    return Vulnerability.query.filter(
        func.lower(Vulnerability.vendor).in_(normalized_vendors),
        Vulnerability.added_at >= week_ago  # ← utilise date d'ajout locale
    ).order_by(Vulnerability.added_at.desc()).all()


def build_html_report(cves):
    """
    Construit le contenu HTML de l'email avec les CVEs récentes.
    """
    rows = ""
    for cve in cves:
        rows += f"""
        <tr>
            <td><a href='https://www.opencve.io/cve/{cve.cve_id}'>{cve.cve_id}</a></td>
            <td>{cve.description or "Sans description"}</td>
            <td>{cve.created_at if cve.created_at else 'N/A'}</td>
            <td>{cve.severity or 'N/A'}</td>
            <td>{cve.vendor or 'Inconnu'}</td>
        </tr>"""

    return f"""
    <html>
    <body>
        <h2>🛡️ Rapport Hebdomadaire HackGuardian</h2>
        <p>Voici les CVEs ajoutées cette semaine pour vos vendeurs abonnés :</p>
        <table border="1" cellpadding="6" cellspacing="0" style="border-collapse:collapse;">
            <tr><th>ID CVE</th><th>Description</th><th>Date</th><th>Gravité</th><th>Vendeur</th></tr>
            {rows}
        </table>
        <p style='margin-top:20px'>Vous recevez ce message car vous avez activé les alertes hebdomadaires dans votre compte HackGuardian.</p>
    </body>
    </html>"""


def send_email(destinataire, contenu_html):
    """
    Envoie un email HTML via SMTP sécurisé (SSL).
    """
    msg = MIMEText(contenu_html, 'html')
    msg['Subject'] = '🛡️ Rapport Hebdomadaire CVE - HackGuardian'
    msg['From'] = EMAIL_SENDER
    msg['To'] = destinataire

    try:
        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as smtp:
            smtp.login(EMAIL_SENDER, EMAIL_PASSWORD)
            smtp.send_message(msg)
            print(f"✅ Email envoyé à {destinataire}")
    except Exception as e:
        print(f"❌ Erreur lors de l’envoi à {destinataire} : {e}")


def send_weekly_report():
    """
    Fonction principale appelée depuis la CLI ou une route Flask.
    Envoie les rapports aux utilisateurs abonnés.
    """
    with current_app.app_context():
        users = Subscriber.query.filter(
            Subscriber.frequence.in_(['hebdomadaire', 'les_deux'])
        ).all()

        for user in users:
            vendor_list = user.get_vendors_list()
            print(f"\n🧪 {user.email} est abonné à : {vendor_list}")

            if not vendor_list:
                print("⏭️ Aucun vendeur abonné.")
                continue

            cves = get_weekly_cves_for_vendors(vendor_list)
            print(f"🔎 {len(cves)} CVE(s) trouvée(s) pour {user.email}")

            for cve in cves:
                print(f" - {cve.cve_id} | {cve.vendor} | ajouté le {cve.added_at.strftime('%Y-%m-%d')}")

            if not cves:
                continue

            report = build_html_report(cves)
            send_email(user.email, report)
