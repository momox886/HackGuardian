
from flask import Blueprint, render_template, request, redirect, url_for, flash
import requests
from .models import Vulnerability, Subscriber, Vendor
from . import db
import os
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from . import socketio

from flask_socketio import join_room

main = Blueprint('main', __name__)

USERNAME = 'mopox06'
PASSWORD = '1515F@timata'

# --- Routes Authentification ---
@main.route('/init-vendors')
@login_required
def init_vendors():
    if not current_user.is_admin:
        flash("Accès refusé", "danger")
        return redirect(url_for('main.index'))

    initial_vendors = ['cisco', 'microsoft', 'fortinet', 'apple', 'oracle','python','linux']

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

        user = Subscriber.query.filter_by(email=email).first()
        if not user or not check_password_hash(user.password, password):
            flash("Email ou mot de passe incorrect.", "danger")
            return redirect(url_for('main.login'))

        login_user(user)
        flash("Connexion réussie.", "success")

        if user.is_admin:
            return redirect(url_for('main.admin_dashboard_view'))
        else:
            return redirect(url_for('main.user_dashboard'))

    return render_template('login.html')


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

@main.route('/send-report')
@login_required
def send_report():
    EMAIL_SENDER = os.getenv('EMAIL_SENDER')
    EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD')
    SMTP_SERVER = 'smtp.gmail.com'
    SMTP_PORT = 465

    import smtplib
    from email.message import EmailMessage

    subscribers = Subscriber.query.all()

    if not subscribers:
        flash("Aucun abonné à notifier.", "warning")
        return redirect(url_for('main.index'))

    try:
        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as smtp:
            smtp.login(EMAIL_SENDER, EMAIL_PASSWORD)

            for subscriber in subscribers:
                if not subscriber.vendors:
                    continue
                subscribed_vendors = [v.strip() for v in subscriber.vendors.split(',') if v.strip()]
                vulns = Vulnerability.query.filter(Vulnerability.vendor.in_(subscribed_vendors)).order_by(Vulnerability.created_at.desc()).all()

                if not vulns:
                    continue

                msg = EmailMessage()
                msg['Subject'] = 'Résumé des vulnérabilités pour vos vendeurs abonnés'
                msg['From'] = EMAIL_SENDER
                msg['To'] = subscriber.email

                content = "Voici les vulnérabilités correspondant à vos vendeurs abonnés :\n\n"
                content += "\n".join(
                    [f"- {v.cve_id} | {v.vendor} | {v.severity}\n  {v.description}\n" for v in vulns]
                )
                msg.set_content(content)

                smtp.send_message(msg)
        flash("Emails envoyés avec succès.", "success")
    except Exception as e:
        flash(f"Erreur lors de l'envoi des emails : {e}", "danger")

    return redirect(url_for('main.index'))

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
                if vendor:
                    socketio.emit('new_critical_cve', {
                        'cve_id': vuln.cve_id,
                        'vendor': vendor,
                        'description': vuln.description
                    }, to=vendor)


def enrich_all_cves():
    cves = Vulnerability.query.all()
    for vuln in cves:
        enrich_cve_in_db(vuln.cve_id)

# --- WebSocket handler ---

@socketio.on('join_vendor')
def handle_join_vendor(vendor):
    join_room(vendor)
