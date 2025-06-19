from flask import current_app
from .models import Vulnerability, Subscriber
from datetime import datetime, timedelta
from sqlalchemy import func
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import os
from dotenv import load_dotenv
from markupsafe import escape

load_dotenv()

# Chargement des infos SMTP
EMAIL_SENDER = os.getenv('EMAIL_SENDER')
EMAIL_PASSWORD = os.getenv('MDP')
SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.getenv('SMTP_PORT', 465))

# Limite du nombre de CVEs dans un rapport
MAX_CVES = 20


def get_weekly_cves_for_vendors(vendor_list):
    """
    Récupère les CVE ajoutées cette semaine pour les vendeurs abonnés.
    """
    if not vendor_list:
        return []

    now = datetime.utcnow()
    week_ago = now - timedelta(days=7)
    normalized_vendors = [v.strip().lower() for v in vendor_list]

    return Vulnerability.query.filter(
        func.lower(Vulnerability.vendor).in_(normalized_vendors),
        Vulnerability.added_at >= week_ago
    ).order_by(Vulnerability.added_at.desc()).all()


def get_severity_label(cve):
    """
    Déduit la gravité à partir du meilleur score CVSS disponible.
    """
    for s in [cve.cvss_v4_0_score, cve.cvss_v3_1_score, cve.cvss_v3_0_score, cve.cvss_v2_score]:
        if s:
            try:
                score = float(s)
                if score >= 9.0:
                    return 'Critique'
                elif score >= 7.0:
                    return 'Élevée'
                elif score >= 4.0:
                    return 'Modérée'
                else:
                    return 'Faible'
            except ValueError:
                continue
    return 'N/A'


def build_html_report(cves, was_truncated=False):
    """
    Construit le contenu HTML du rapport.
    """
    rows = ""
    for cve in cves:
        rows += f"""
        <tr>
            <td><a href='https://www.opencve.io/cve/{cve.cve_id}'>{cve.cve_id}</a></td>
            <td>{escape(cve.description) if cve.description else "Sans description"}</td>
            <td>{cve.added_at.strftime('%Y-%m-%d') if cve.added_at else 'N/A'}</td>
            <td>{get_severity_label(cve)}</td>
            <td>{escape(cve.vendor) if cve.vendor else 'Inconnu'}</td>
        </tr>"""

    info_note = ""
    if was_truncated:
        info_note = f"""
        <p style="color:red;"><strong>⚠️ La liste a été tronquée à {MAX_CVES} CVEs maximum pour garantir la délivrabilité de l’email.</strong></p>
        """

    return f"""
    <html>
    <head>
        <meta charset="utf-8">
    </head>
    <body>
        <h2>🛡️ Rapport Hebdomadaire HackGuardian</h2>
        <p>Voici les CVEs ajoutées cette semaine pour vos vendeurs abonnés :</p>
        {info_note}
        <table border="1" cellpadding="6" cellspacing="0" style="border-collapse:collapse;">
            <tr>
                <th>ID CVE</th>
                <th>Description</th>
                <th>Date</th>
                <th>Gravité</th>
                <th>Vendeur</th>
            </tr>
            {rows}
        </table>
        <p style='margin-top:20px'>Vous recevez ce message car vous avez activé les alertes hebdomadaires dans votre compte HackGuardian.</p>
    </body>
    </html>"""


def send_email(destinataire, contenu_html):
    """
    Envoie un email HTML correctement encodé à un utilisateur.
    """
    msg = MIMEMultipart("alternative")
    msg['Subject'] = '🛡️ Rapport Hebdomadaire CVE - HackGuardian'
    msg['From'] = EMAIL_SENDER
    msg['To'] = destinataire

    part_html = MIMEText(contenu_html, 'html', 'utf-8')
    msg.attach(part_html)

    try:
        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as smtp:
            smtp.login(EMAIL_SENDER, EMAIL_PASSWORD)
            smtp.send_message(msg)
            print(f"✅ Email envoyé à {destinataire}")
            print(f"📏 Longueur du contenu : {len(contenu_html)} caractères")
    except Exception as e:
        print(f"❌ Erreur lors de l’envoi à {destinataire} : {e}")


def send_weekly_report():
    """
    Fonction principale : envoie le rapport à tous les utilisateurs abonnés.
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

            was_truncated = len(cves) > MAX_CVES
            report = build_html_report(cves[:MAX_CVES], was_truncated=was_truncated)
            send_email(user.email, report)
