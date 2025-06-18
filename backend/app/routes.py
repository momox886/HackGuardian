from .decorators import admin_required, superadmin_required
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
import requests
from .models import Vulnerability, Subscriber, Vendor, CriticalCveSent, CriticalCvePushed, Message

from . import db
import os
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from . import socketio
from .models import LoginAttempt
from datetime import datetime
import smtplib
from email.message import EmailMessage
from flask_socketio import join_room, emit, leave_room
from  dotenv import load_dotenv
import pyotp
import qrcode
import io
from markupsafe import escape
from base64 import b64encode
import html
from .Crypto import encrypt_data  # Assure-toi que cet import est correct
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
        name = request.form.get('name')
        first_name = request.form.get('first_name')
        organization = request.form.get('organization')

        allowed_organizations = ['Naval Group', 'Département du Var', 'ISEN Méditerranée']

        # Vérification des champs
        if not all([email, password, password_confirm, name, first_name, organization]):
            flash("Tous les champs sont obligatoires.", "warning")
            return redirect(url_for('main.register'))

        if organization not in allowed_organizations:
            flash("Organisation invalide.", "danger")
            return redirect(url_for('main.register'))

        if password != password_confirm:
            flash("Les mots de passe ne correspondent pas.", "danger")
            return redirect(url_for('main.register'))

        # Vérifie si l'email existe déjà (en déchiffrant)
        existing_users = Subscriber.query.all()
        if any(u.email == email for u in existing_users):
            flash("Email déjà enregistré.", "warning")
            return redirect(url_for('main.register'))

        hashed_password = generate_password_hash(password)

        new_user = Subscriber(
            email=email,
            password=hashed_password,
            name=name,
            first_name=first_name,
            organization=organization,
            vendors=''  # Aucun vendeur abonné à l’inscription
        )

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

        # ⚠️ Recherche manuelle à cause du chiffrement
        users = Subscriber.query.all()
        user = next((u for u in users if u.email == email), None)

        success = user and check_password_hash(user.password, password)

        login_attempt = LoginAttempt(email=email, success=bool(success), ip_address=ip)
        db.session.add(login_attempt)
        db.session.commit()

        if not success:
            flash("Email ou mot de passe incorrect.", "danger")
            return redirect(url_for('main.login'))

        if user.role == 'superadmin' and not user.twofa_secret:
            session['pre_2fa_user_id'] = user.id
            flash("2FA requis pour les superadmins. Veuillez l’activer avant de continuer.", "warning")
            return redirect(url_for('main.enable_2fa'))

        if user.twofa_secret:
            session['pre_2fa_user_id'] = user.id
            return redirect(url_for('main.verify_2fa'))

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

    # Les vendeurs auxquels l'utilisateur est abonné (déchiffrés)
    user_vendors = current_user.get_vendors_list()

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

    current_vendors = subscriber.get_vendors_list()

    if vendor_name in current_vendors:
        flash(f"Déjà abonné à {vendor_name}.", "info")
    else:
        current_vendors.append(vendor_name)
        subscriber.set_vendors_list(current_vendors)  # Chiffre la nouvelle liste
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

@main.route('/test-chat')
@login_required
def test_chat():
    return render_template('chat.html', user=current_user)

@main.route('/chat')
@login_required
def chat():
    from .models import Message, Subscriber

    room = 'general'
    messages = Message.query.filter_by(room=room).order_by(Message.timestamp).all()

    all_users = Subscriber.query.all() if current_user.role in ['admin', 'superadmin'] else []

    return render_template(
        'chat.html',
        user=current_user,
        room=room,
        messages=messages,
        all_users=all_users  # pour le menu déroulant admin
    )

@main.route('/conversations')
@login_required
def conversations():
    from .models import Message, Subscriber

    if current_user.role in ['admin', 'superadmin']:
        users = Subscriber.query.filter(Subscriber.id != current_user.id).all()
    else:
        users = Subscriber.query.filter(Subscriber.id != current_user.id).all()

    latest_messages = {}
    for user in users:
        room = f"dm_{min(user.id, current_user.id)}_{max(user.id, current_user.id)}"
        last = Message.query.filter_by(room=room).order_by(Message.timestamp.desc()).first()
        if last:
            latest_messages[room] = {
                "content": last.content[:30] + ("..." if len(last.content) > 30 else ""),
                "timestamp": last.timestamp.strftime('%H:%M')
            }

    return render_template(
        'conversations.html',
        user=current_user,
        users=users,
        latest_messages=latest_messages
    )

@main.route('/get_messages/<room>')
@login_required
def get_messages(room):
    from .models import Message
    messages = Message.query.filter_by(room=room).order_by(Message.timestamp.asc()).all()
    return [{
        "sender_email": msg.sender_email,
        "content": msg.content,
        "timestamp": msg.timestamp.strftime('%Y-%m-%d %H:%M:%S')
    } for msg in messages]


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
                vendor = vendor.strip().lower()
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

# Liste de gros mots à filtrer (ajustable)
BAD_WORDS = {
    "pute", "enculé", "merde", "con", "connard", "salope", "pd", "batard", "fdp",
    "chienne", "encule", "enculer", "fils de pute", "nique", "ta mère", "ntm",
    "bâtard", "salaud", "trou du cul", "bouffon", "clochard",
    "putain"
}

def contains_bad_words(text):
    """Vérifie si le message contient des mots interdits (langue française)"""
    lower_text = text.lower()
    return any(bad_word in lower_text for bad_word in BAD_WORDS)

# --- WebSocket handler ---

@socketio.on('join_vendor')
def handle_join_vendor(vendor):
    join_room(vendor)

@socketio.on('join')
def handle_join(data):
    room = data.get("room")
    join_room(room)

@socketio.on('leave')
def handle_leave(data):
    room = data.get("room")
    leave_room(room)

@socketio.on('send_message')
def handle_send_message(data):
    username = data.get('username')
    user_id = data.get('user_id')
    raw_message = data.get('message', '')
    room = data.get('room')

    clean_message = raw_message.strip()

    if contains_bad_words(clean_message):
        emit("receive_message", {
            "username": "Système",
            "message": "🚫 Message bloqué pour contenu inapproprié."
        }, room=room)
        return

    if room and clean_message:
        msg = Message(
            sender_id=user_id,
            sender_email=current_user.email,  # 👈 le setter s'occupe du chiffrement
            content=clean_message,            # 👈 idem, sera chiffré
            room=room
        )

        db.session.add(msg)
        db.session.commit()

        emit("receive_message", {
            "username": username,
            "message": clean_message,
            "room": room
        }, room=room)