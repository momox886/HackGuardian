from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
import requests
from dotenv import load_dotenv
import logging

# Configuration du logging
logging.basicConfig()
logging.getLogger('apscheduler').setLevel(logging.DEBUG)
load_dotenv()

# Initialisation de l'application Flask
app = Flask(__name__)
app.secret_key = os.urandom(24)  # Clé secrète sécurisée

# Configuration de la base de données SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Chargement des variables d'environnement
load_dotenv()

# Configuration OpenCVE
OPENCVE_USERNAME = 'mopox06'
OPENCVE_PASSWORD = os.getenv('PASSWORD')
BASE_OPENCVE_URL = 'https://app.opencve.io/api'

# Modèle Utilisateur
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    nom = db.Column(db.String(100), nullable=True)
    prenom = db.Column(db.String(100), nullable=True)
    username = db.Column(db.String(100), nullable=True)
    password = db.Column(db.String(255), nullable=False)
    frequence = db.Column(db.String(20), nullable=False, default='quotidien')

# Modèle Vendeur
class Vendor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    website = db.Column(db.String(200))
    contact_email = db.Column(db.String(120))

# Modèle CVE
class CVE(db.Model):
    id = db.Column(db.String(20), primary_key=True)  # Format CVE-XXXX-XXXX
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    product = db.Column(db.String(100), nullable=False)
    severity = db.Column(db.String(20), nullable=False)  # Critique, Haute, Moyenne, Faible
    date_published = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    vendor_id = db.Column(db.Integer, db.ForeignKey('vendor.id'))
    vendor = db.relationship('Vendor', backref='cves')
    source = db.Column(db.String(100))
    link = db.Column(db.String(200))
    cvss_score = db.Column(db.Float)
    cvss_vector = db.Column(db.String(100))

# Fonctions API optimisées
def fetch_vendors(page=1):
    try:
        response = requests.get(f'{BASE_OPENCVE_URL}/vendors?page={page}', 
                             auth=(OPENCVE_USERNAME, OPENCVE_PASSWORD),
                             timeout=10)
        return response.json().get('results', []) if response.status_code == 200 else []
    except:
        return []

def fetch_cves(vendor=None, page=1):
    try:
        url = f'{BASE_OPENCVE_URL}/cve?page={page}'
        if vendor: url += f'&vendor={vendor}'
        response = requests.get(url, 
                             auth=(OPENCVE_USERNAME, OPENCVE_PASSWORD),
                             timeout=10)
        return response.json().get('results', []) if response.status_code == 200 else []
    except:
        return []

def fetch_cve_details(cve_id):
    try:
        response = requests.get(f'{BASE_OPENCVE_URL}/cve/{cve_id}',
                             auth=(OPENCVE_USERNAME, OPENCVE_PASSWORD),
                             timeout=10)
        return response.json() if response.status_code == 200 else None
    except:
        return None

# Synchronisation optimisée
def sync_vendors():
    with app.app_context():
        try:
            vendors = fetch_vendors(page=1)
            if vendors:
                for vendor in vendors:
                    if not Vendor.query.filter_by(name=vendor['name']).first():
                        db.session.add(Vendor(
                            name=vendor['name'],
                            website=f"https://nvd.nist.gov/vuln/search/vendor?vendorName={vendor['name']}"
                        ))
                db.session.commit()
                app.logger.info(f"Sync vendors: {len(vendors)} traités")
        except Exception as e:
            app.logger.error(f"Erreur sync vendors: {str(e)}")

def sync_cves():
    with app.app_context():
        try:
            vendors = Vendor.query.limit(3).all()  # Limité à 3 vendeurs par sync
            for vendor in vendors:
                cves = fetch_cves(vendor.name, page=1)
                if cves:
                    for cve in cves:
                        if not CVE.query.get(cve['cve_id']):
                            details = fetch_cve_details(cve['cve_id'])
                            if details:
                                cvss = details.get('metrics', {}).get('cvssV3_1', {}).get('data', {})
                                db.session.add(CVE(
                                    id=cve['cve_id'],
                                    title=details.get('summary', ''),
                                    description=details.get('summary', ''),
                                    product=details.get('vendors', [''])[0],
                                    severity=cvss.get('severity', 'Inconnue'),
                                    vendor_id=vendor.id,
                                    source="OpenCVE",
                                    link=f"https://www.opencve.io/cve/{cve['cve_id']}",
                                    date_published=datetime.strptime(cve['created_at'], '%Y-%m-%dT%H:%M:%S.%fZ'),
                                    cvss_score=cvss.get('score'),
                                    cvss_vector=cvss.get('vector')
                                ))
                    db.session.commit()
                    app.logger.info(f"Sync CVE pour {vendor.name}: {len(cves)} traités")
        except Exception as e:
            app.logger.error(f"Erreur sync CVE: {str(e)}")

# Planification toutes les minutes
scheduler = BackgroundScheduler()
scheduler.add_job(sync_vendors, 'interval', minutes=1, max_instances=1)
scheduler.add_job(sync_cves, 'interval', minutes=1, max_instances=1)
scheduler.start()

# Création de la base de données
with app.app_context():
    db.create_all()

# Routes d'authentification
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        nom = request.form['nom']
        prenom = request.form['prenom']
        username = request.form['username'] 
        frequence = request.form['frequence']

        if User.query.filter_by(email=email).first():
            return "Cet email est déjà utilisé.", 400
        if User.query.filter_by(username=username).first():
            return "Ce nom d'utilisateur est déjà utilisé.", 400

        hashed_password = generate_password_hash(password)
        new_user = User(
            email=email, 
            password=hashed_password, 
            frequence=frequence, 
            nom=nom, 
            prenom=prenom, 
            username=username
        )
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('dashboard'))

        return "Email ou mot de passe incorrect.", 401

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# Dashboard et gestion des données
@app.route('/dashboard')
def dashboard():
    if not session.get('user_id'):
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    vendors = Vendor.query.all()
    cves = CVE.query.order_by(CVE.date_published.desc()).limit(10).all()
    return render_template('dashboard.html', user=user, vendors=vendors, cves=cves)

@app.route('/update_notification', methods=['POST'])
def update_notification():
    if not session.get('user_id'):
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    user.frequence = request.form['frequence']
    db.session.commit()
    return redirect(url_for('dashboard'))

# Gestion des vendeurs
@app.route('/add_vendor', methods=['POST'])
def add_vendor():
    if not session.get('user_id'):
        return redirect(url_for('login'))
    
    name = request.form['name']
    website = request.form['website']
    contact_email = request.form['contact_email']

    if Vendor.query.filter_by(name=name).first():
        return "Ce vendeur existe déjà.", 400

    new_vendor = Vendor(name=name, website=website, contact_email=contact_email)
    db.session.add(new_vendor)
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/search_vendors')
def search_vendors():
    if not session.get('user_id'):
        return redirect(url_for('login'))
    
    query = request.args.get('query', '')
    vendors = Vendor.query.filter(Vendor.name.contains(query)).all()
    return render_template('vendor_results.html', vendors=vendors)

# Gestion des CVE
@app.route('/add_cve', methods=['POST'])
def add_cve():
    if not session.get('user_id'):
        return redirect(url_for('login'))
    
    try:
        cve_id = request.form['cve_id']
        title = request.form['title']
        description = request.form['description']
        product = request.form['product']
        severity = request.form['severity']
        vendor_id = request.form['vendor_id']
        source = request.form['source']
        link = request.form['link']
        cvss_score = request.form.get('cvss_score', 0.0)
        cvss_vector = request.form.get('cvss_vector', '')

        if CVE.query.get(cve_id):
            return "Cette CVE existe déjà.", 400

        new_cve = CVE(
            id=cve_id,
            title=title,
            description=description,
            product=product,
            severity=severity,
            vendor_id=vendor_id,
            source=source,
            link=link,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector
        )
        db.session.add(new_cve)
        db.session.commit()
        return redirect(url_for('dashboard'))
    except Exception as e:
        return f"Erreur: {str(e)}", 400

@app.route('/search_cves')
def search_cves():
    if not session.get('user_id'):
        return redirect(url_for('login'))
    
    product = request.args.get('product', '')
    severity = request.args.get('severity', '')
    vendor_id = request.args.get('vendor_id', '')

    query = CVE.query
    if product:
        query = query.filter(CVE.product.contains(product))
    if severity:
        query = query.filter_by(severity=severity)
    if vendor_id:
        query = query.filter_by(vendor_id=vendor_id)

    cves = query.order_by(CVE.date_published.desc()).all()
    return render_template('cve_results.html', cves=cves)

# API pour les CVE
@app.route('/api/cves')
def get_cves():
    cves = CVE.query.order_by(CVE.date_published.desc()).all()
    return jsonify([{
        'id': cve.id,
        'title': cve.title,
        'product': cve.product,
        'severity': cve.severity,
        'date': cve.date_published.strftime('%Y-%m-%d'),
        'source': cve.source,
        'link': cve.link,
        'vendor': cve.vendor.name if cve.vendor else '',
        'cvss_score': cve.cvss_score,
        'cvss_vector': cve.cvss_vector
    } for cve in cves])

# Synchronisation manuelle
@app.route('/sync')
def manual_sync():
    if not session.get('user_id'):
        return redirect(url_for('login'))
    
    sync_vendors()
    sync_cves()
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    # Synchronisation initiale
    with app.app_context():
        sync_vendors()
        sync_cves()
    
    app.run(debug=True)