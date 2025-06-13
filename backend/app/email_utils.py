import smtplib
from email.message import EmailMessage
import os
from flask import flash
from .models import Vulnerability, Subscriber


EMAIL_SENDER = os.getenv('EMAIL_SENDER')
EMAIL_PASSWORD = os.getenv('MDP')

def send_vulnerability_report():
    from .models import Vulnerability, Subscriber

    vulns = Vulnerability.query.order_by(Vulnerability.created_at.desc()).all()
    subscribers = Subscriber.query.all()

    for sub in subscribers:
        if not sub.vendors:
            continue
        vendor_list = [v.strip() for v in sub.vendors.split(',') if v.strip()]
        filtered_vulns = [v for v in vulns if v.vendor in vendor_list]

        if not filtered_vulns:
            continue

        msg = EmailMessage()
        msg['Subject'] = 'Alertes CVE personnalisées'
        msg['From'] = EMAIL_SENDER
        msg['To'] = sub.email
        msg.set_content("\n".join(
            [f"- {v.cve_id} | {v.vendor} | {v.severity}\n  {v.description}" for v in filtered_vulns]
        ))

        try:
            with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
                smtp.login(EMAIL_SENDER, EMAIL_PASSWORD)
                smtp.send_message(msg)
        except Exception as e:
            print(f"[ERREUR] Envoi pour {sub.email} : {e}")
