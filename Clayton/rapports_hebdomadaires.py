
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText

# === Flask + SQLite (utilisateurs) ===
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    nom = db.Column(db.String(100))
    prenom = db.Column(db.String(100))
    username = db.Column(db.String(100))
    password = db.Column(db.String(255), nullable=False)
    frequence = db.Column(db.String(20), default='quotidien')

# === Connexion PostgreSQL (OpenCVE) ===
pg_user = 'opencve'
pg_pass = 'opencve'
pg_host = '172.18.0.4'
pg_port = '5432'
pg_db   = 'opencve'
pg_url = f'postgresql://{pg_user}:{pg_pass}@{pg_host}:{pg_port}/{pg_db}'
pg_engine = create_engine(pg_url)
PGSession = sessionmaker(bind=pg_engine)
pg_session = PGSession()

# === Récupération des CVEs de la dernière semaine ===
def get_weekly_cves():
    now = datetime.utcnow()
    week_ago = now - timedelta(days=7)
    results = pg_session.execute(text("""
        SELECT cve_id, title, created_at, metrics
        FROM opencve_cves
        WHERE created_at >= :since
        ORDER BY created_at DESC
    """"), {'since': week_ago}).fetchall()
    return results

# === Génération HTML du mail ===
def build_html_report(cves):
    rows = ""
    for cve in cves:
        cvss = cve.metrics.get('cvss2', {}).get('score') if cve.metrics else 'N/A'
        rows += f"""
        <tr>
            <td><a href='https://www.opencve.io/cve/{cve.cve_id}'>{cve.cve_id}</a></td>
            <td>{cve.title or "Sans titre"}</td>
            <td>{cve.created_at.strftime('%Y-%m-%d')}</td>
            <td>{cvss}</td>
        </tr>"""
    return f"""
    <html>
    <body>
        <h2>🛡️ Rapport Hebdomadaire HackGuardian</h2>
        <p>Voici les CVEs publiées cette semaine :</p>
        <table border="1" cellpadding="6" cellspacing="0">
            <tr><th>ID CVE</th><th>Titre</th><th>Date</th><th>CVSS</th></tr>
            {rows}
        </table>
        <p style='margin-top:20px'>Vous recevez ce message car vous avez activé les alertes hebdomadaires dans votre compte HackGuardian.</p>
    </body>
    </html>"""

# === Envoi d’un email HTML via SMTP ===
def send_email(destinataire, contenu_html):
    msg = MIMEText(contenu_html, 'html')
    msg['Subject'] = '🛡️ Rapport Hebdomadaire CVE - HackGuardian'
    msg['From'] = 'alertes@hackguardian.local'
    msg['To'] = destinataire

    with smtplib.SMTP('localhost') as smtp:
        smtp.send_message(msg)

# === Main : envoi aux utilisateurs hebdomadaires ===
with app.app_context():
    weekly_cves = get_weekly_cves()
    if not weekly_cves:
        print("📭 Aucun CVE publié cette semaine.")
    else:
        report = build_html_report(weekly_cves)
        utilisateurs = User.query.filter_by(frequence='hebdomadaire').all()
        for user in utilisateurs:
            print(f"✉️ Envoi à {user.email}")
            send_email(user.email, report)
