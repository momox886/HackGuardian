from .decorators import admin_required, superadmin_required
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
import requests
from .models import Vulnerability, Subscriber, Vendor, CriticalCveSent, CriticalCvePushed

from . import db
import os
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from . import socketio
from .models import LoginAttempt
from datetime import datetime
import smtplib
from email.message import EmailMessage
from flask_socketio import join_room
from  dotenv import load_dotenv
import pyotp
import qrcode
import io
from base64 import b64encode
load_dotenv()

main = Blueprint('main', __name__)

USERNAME = 'mopox06'
PASSWORD = '1515F@timata'

# --- Routes Authentification ---
@main.route('/init-vendors')
@admin_required
def init_vendors():
    initial_vendors = ['cisco', 'microsoft', 'fortinet', 'apple', 'oracle', 'python', 'linux']

    for name in initial_vendors:
        if not Vendor.query.filter_by(name=name).first():
            db.session.add(Vendor(name=name))

    db.session.commit()
    flash("Vendeurs initialisés avec succès.", "success")
    return redirect(url_for('main.admin_dashboard_view'))



@main.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        password_confirm = request.form.get('password_confirm')

        if not email or not password or not password_confirm:
            flash("Tous les champs sont obligatoires.", "warning")
            return redirect(url_for('main.register'))

        if password != password_confirm:
            flash("Les mots de passe ne correspondent pas.", "danger")
            return redirect(url_for('main.register'))

        if Subscriber.query.filter_by(email=email).first():
            flash("Email déjà enregistré.", "warning")
            return redirect(url_for('main.register'))

        hashed_password = generate_password_hash(password)
        new_user = Subscriber(email=email, password=hashed_password, vendors='')
        db.session.add(new_user)
        db.session.commit()
        flash("Inscription réussie. Connectez-vous.", "success")
        return redirect(url_for('main.login'))

    return render_template('register.html')

@main.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        ip = request.remote_addr or 'unknown'

        user = Subscriber.query.filter_by(email=email).first()
        success = user and check_password_hash(user.password, password)

        # Log tentative de connexion
        login_attempt = LoginAttempt(email=email, success=bool(success), ip_address=ip)
        db.session.add(login_attempt)
        db.session.commit()

        if not success:
            flash("Email ou mot de passe incorrect.", "danger")
            return redirect(url_for('main.login'))

        # 🔐 FORCER les superadmins à activer le 2FA s'il n'est pas encore activé
        if user.role == 'superadmin' and not user.twofa_secret:
            session['pre_2fa_user_id'] = user.id
            flash("2FA requis pour les superadmins. Veuillez l’activer avant de continuer.", "warning")
            return redirect(url_for('main.enable_2fa'))

        # 🔑 Si le 2FA est activé, rediriger vers la vérification
        if user.twofa_secret:
            session['pre_2fa_user_id'] = user.id
            return redirect(url_for('main.verify_2fa'))

        # 🔓 Sinon, connexion directe
        login_user(user)
        flash("Connexion réussie.", "success")

        if user.role == 'superadmin':
            return redirect(url_for('main.superadmin_dashboard_view'))
        elif user.role == 'admin':
            return redirect(url_for('main.admin_dashboard_view'))
        else:
            return redirect(url_for('main.user_dashboard'))

    return render_template('login.html')


@main.route('/enable-2fa')
def enable_2fa():
    if not current_user.is_authenticated and 'pre_2fa_user_id' not in session:
        flash("Vous devez être connecté pour activer le 2FA.", "danger")
        return redirect(url_for('main.login'))

    user_id = session.get('pre_2fa_user_id') or current_user.id
    user = Subscriber.query.get(user_id)

    if not user.twofa_secret:
        secret = pyotp.random_base32()
        user.twofa_secret = secret
        db.session.commit()
    else:
        secret = user.twofa_secret

    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=user.email, issuer_name="MonApp Flask CVE")

    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    qr_code = b64encode(buf.getvalue()).decode()

    return render_template('enable_2fa.html', qr_code=qr_code, secret=secret)


@main.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():

    user_id = session.get('pre_2fa_user_id')
    if not user_id:
        flash("Session expirée. Veuillez vous reconnecter.", "warning")
        return redirect(url_for('main.login'))

    user = Subscriber.query.get(user_id)
    if request.method == 'POST':
        code = request.form.get('code')
        totp = pyotp.TOTP(user.twofa_secret)
        if totp.verify(code):
            login_user(user)
            session.pop('pre_2fa_user_id', None)
            flash("Connexion 2FA réussie.", "success")
            return redirect(url_for('main.superadmin_dashboard_view') if user.role == 'superadmin'
                            else url_for('main.admin_dashboard_view') if user.role == 'admin'
                            else url_for('main.user_dashboard'))
        else:
            flash("Code 2FA invalide.", "danger")

    return render_template('verify_2fa.html')

@main.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Déconnexion réussie.", "info")
    return redirect(url_for('main.index'))

# --- Routes principales ---

@main.route('/')
def index():
    vulnerabilities = Vulnerability.query.order_by(Vulnerability.created_at.desc()).all()
    return render_template('vulnerabilities.html', vulnerabilities=vulnerabilities)

@main.route('/vulnerabilities')
def list_vulnerabilities():
    vulnerabilities = Vulnerability.query.order_by(Vulnerability.created_at.desc()).all()
    return render_template('vulnerabilities.html', vulnerabilities=vulnerabilities)

@main.route('/user-dashboard')
@login_required
def user_dashboard():
    # Tous les vendeurs (pour le <select>)
    all_vendors = [v.name for v in Vendor.query.all()]

    # Les vendeurs auxquels l'utilisateur est abonné
    user_vendors = []
    if current_user.vendors:
        user_vendors = [v.strip() for v in current_user.vendors.split(',') if v.strip()]

    # Charger les vulnérabilités filtrées selon les vendeurs abonnés
    vulnerabilities = []
    if user_vendors:
        vulnerabilities = Vulnerability.query.filter(Vulnerability.vendor.in_(user_vendors))\
                          .order_by(Vulnerability.created_at.desc()).all()

    return render_template(
        'user_dashboard.html',
        vendors=all_vendors,
        user=current_user,
        user_vendors=user_vendors,
        vulnerabilities=vulnerabilities
    )


@main.route('/subscribe-vendor', methods=['POST'])
@login_required
def subscribe_vendor():
    vendor_name = request.form.get('vendor')

    # Vérifier si ce vendeur existe dans la table Vendor
    vendor_obj = Vendor.query.filter_by(name=vendor_name).first()
    if not vendor_obj:
        flash("Ce vendeur n'existe pas.", "danger")
        return redirect(url_for('main.user_dashboard'))

    subscriber = Subscriber.query.get(current_user.id)
    if not subscriber:
        flash("Utilisateur non trouvé.", "warning")
        return redirect(url_for('main.user_dashboard'))

    # Extraire et nettoyer les abonnements existants
    current_vendors = [v.strip() for v in (subscriber.vendors or "").split(',') if v.strip()]

    if vendor_name in current_vendors:
        flash(f"Déjà abonné à {vendor_name}.", "info")
    else:
        current_vendors.append(vendor_name)
        subscriber.vendors = ','.join(current_vendors)
        db.session.commit()
        flash(f"Abonnement à {vendor_name} ajouté.", "success")

    return redirect(url_for('main.user_dashboard'))


@main.route('/admin-dashboard', methods=['GET', 'POST'])
@login_required
def admin_dashboard_view():
    if request.method == 'POST':
        vendor = request.form.get('vendor')
        page = request.form.get('page', '1')
        url = f'https://app.opencve.io/api/cve?page={page}&vendor={vendor}'
        response = requests.get(url, auth=(USERNAME, PASSWORD))

        if response.status_code == 200:
            data = response.json()
            results = data.get('results', [])

            for item in results:
                cve_id = item.get('cve_id')
                if not Vulnerability.query.filter_by(cve_id=cve_id).first():
                    vuln = Vulnerability(
                        cve_id=cve_id,
                        description=item.get('description'),
                        created_at=item.get('created_at'),
                        updated_at=item.get('updated_at'),
                        vendor=vendor,
                        severity=item.get('cvss', 'Unknown')
                    )
                    db.session.add(vuln)

                    if vuln.severity.lower() == 'critical':
                        socketio.emit('new_critical_cve', {
                            'cve_id': vuln.cve_id,
                            'vendor': vendor,
                            'description': vuln.description
                        }, to=vendor)

            db.session.commit()
            enrich_all_cves()
            flash(f"{len(results)} vulnérabilité(s) ajoutée(s) pour {vendor}.", "success")
        else:
            flash("Erreur lors de la récupération des données.", "danger")

        return redirect(url_for('main.admin_dashboard_view'))

    vulns = Vulnerability.query.order_by(Vulnerability.created_at.desc()).limit(20).all()
    subscribers = Subscriber.query.all()
    return render_template('admin_dashboard.html', vulns=vulns, subscribers=subscribers)


@main.route('/test-page')
def test_socket_page():
    vendor = 'Cisco'  # remplace par un nom de vendeur existant si tu veux
    return render_template('test_socket.html', vendor=vendor)  # on passe vendor à la page


@main.route('/manual-test')
def manual_socket_test():
    vendor = 'Cisco'
    socketio.emit('new_critical_cve', {
        'cve_id': 'CVE-2025-TEST',
        'vendor': vendor,
        'description': 'Ceci est un test manuel via /manual-test'
    }, to=vendor)
    return "Message envoyé via WebSocket !"

@main.route('/update-user-role', methods=['POST'])
@superadmin_required
def update_user_role():
    user_id = request.form.get('user_id')
    new_role = request.form.get('new_role')

    user = Subscriber.query.get(user_id)
    if user:
        user.role = new_role
        db.session.commit()
        flash(f"Rôle de {user.email} mis à jour en {new_role}.", "success")
    else:
        flash("Utilisateur introuvable.", "danger")

    return redirect(url_for('main.superadmin_dashboard_view'))

@main.route('/superadmin-dashboard')
@superadmin_required
def superadmin_dashboard_view():
    users = Subscriber.query.all()
    login_attempts = LoginAttempt.query.order_by(LoginAttempt.timestamp.desc()).limit(100).all()
    return render_template('superadmin_dashboard.html', users=users, login_attempts=login_attempts)


@main.route('/export-logs')
@superadmin_required
def export_logs():
    from flask import Response
    import csv
    logs = LoginAttempt.query.order_by(LoginAttempt.timestamp.desc()).all()

    def generate():
        yield 'email,success,ip_address,timestamp\n'
        for log in logs:
            yield f'{log.email},{log.success},{log.ip_address},{log.timestamp}\n'

    return Response(generate(), mimetype='text/csv',
                    headers={"Content-Disposition": "attachment;filename=logs.csv"})

# --- Enrichissement CVE ---


def enrich_cve_in_db(cve_id):
    url = f'https://app.opencve.io/api/cve/{cve_id}'
    response = requests.get(url, auth=(USERNAME, PASSWORD))
    if response.status_code != 200:
        return

    data = response.json()
    cvss_data = data.get('metrics', {}).get('cvssV3_1', {}).get('data', {})
    cwes = ', '.join(data.get('weaknesses', []))
    vendors = ', '.join(data.get('vendors', []))
    exploited = bool(data.get('exploited'))

    vuln = Vulnerability.query.filter_by(cve_id=cve_id).first()
    if vuln:
        vuln.cvss_v3_score = cvss_data.get('score', '')
        vuln.cvss_v3_vector = cvss_data.get('vector', '')
        vuln.cwes = cwes
        vuln.vendors = vendors
        vuln.exploited = exploited
        db.session.commit()

        try:
            score = float(vuln.cvss_v3_score or 0)
        except ValueError:
            score = 0.0

        if score >= 9.0:
            for vendor in vendors.split(','):
                vendor = vendor.strip()
                if not vendor:
                    continue

                # ✅ Vérifier si WebSocket déjà envoyé
                already_pushed = CriticalCvePushed.query.filter_by(
                    cve_id=cve_id,
                    vendor=vendor
                ).first()

                if not already_pushed:
                    socketio.emit('new_critical_cve', {
                        'cve_id': vuln.cve_id,
                        'vendor': vendor,
                        'description': vuln.description
                    }, to=vendor)

                    db.session.add(CriticalCvePushed(cve_id=cve_id, vendor=vendor))

                # ✅ Envoi email si nécessaire
                send_critical_cve_email(vendor, vuln)

            db.session.commit()

def send_critical_cve_email(vendor_name, vuln):
    EMAIL_SENDER = os.getenv('EMAIL_SENDER')
    EMAIL_PASSWORD = os.getenv('MDP')
    SMTP_SERVER = 'smtp.gmail.com'
    SMTP_PORT = 465

    if not EMAIL_SENDER or not EMAIL_PASSWORD:
        print("[ERREUR] EMAIL_SENDER ou EMAIL_PASSWORD non définis.")
        return

    Subscribers = Subscriber.query.all()

    try:
        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as smtp:
            smtp.login(EMAIL_SENDER, EMAIL_PASSWORD)

            for subscriber in Subscribers:
                if not subscriber.vendors:
                    continue

                subscribed_vendors = [v.strip().lower() for v in subscriber.vendors.split(',') if v.strip()]
                if vendor_name.lower() not in subscribed_vendors:
                    continue

                # ✅ Vérifier si déjà envoyé
                exists = CriticalCveSent.query.filter_by(
                    subscriber_email=subscriber.email,
                    cve_id=vuln.cve_id,
                    vendor=vendor_name
                ).first()

                if exists:
                    continue  # Déjà envoyé

                msg = EmailMessage()
                msg['Subject'] = f'[CRITIQUE] Nouvelle CVE détectée - {vuln.cve_id}'
                msg['From'] = EMAIL_SENDER
                msg['To'] = subscriber.email

                content = f"""Bonjour,

Une nouvelle vulnérabilité critique a été détectée pour le vendeur : {vendor_name}

ID CVE : {vuln.cve_id}
Gravité : Critique
Description :
{vuln.description}

Cordialement,
Votre système de veille CVE.
"""
                msg.set_content(content)
                smtp.send_message(msg)

                # ✅ Enregistrer que l'email a été envoyé
                record = CriticalCveSent(
                    subscriber_email=subscriber.email,
                    cve_id=vuln.cve_id,
                    vendor=vendor_name
                )
                db.session.add(record)

            db.session.commit()

    except Exception as e:
        print(f"[ERREUR] Envoi email critique : {e}")


def enrich_all_cves():
    cves = Vulnerability.query.all()
    for vuln in cves:
        enrich_cve_in_db(vuln.cve_id)

# --- WebSocket handler ---

@socketio.on('join_vendor')
def handle_join_vendor(vendor):
    join_room(vendor)
