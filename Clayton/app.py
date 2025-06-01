from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime
from dotenv import load_dotenv
import logging
from sqlalchemy import text, create_engine
from sqlalchemy.orm import sessionmaker

# Initialisation
app = Flask(__name__)
app.secret_key = os.urandom(24)

# Base de données SQLite interne
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Connexion à la base OpenCVE PostgreSQL
username = 'opencve'
password = 'opencve'
host = '172.18.0.4'
port = '5432'
database = 'opencve'
db_url = f'postgresql://{username}:{password}@{host}:{port}/{database}'
opencve_engine = create_engine(db_url)
OpenCVESession = sessionmaker(bind=opencve_engine)
opencve_session = OpenCVESession()

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(), logging.FileHandler('app.log')]
)
logger = logging.getLogger(__name__)

# Modèle utilisateur uniquement
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    nom = db.Column(db.String(100))
    prenom = db.Column(db.String(100))
    username = db.Column(db.String(100))
    password = db.Column(db.String(255), nullable=False)
    frequence = db.Column(db.String(20), default='quotidien')

# Routes
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
        new_user = User(email=email, password=hashed_password, nom=nom, prenom=prenom,
                        username=username, frequence=frequence)
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

@app.route('/dashboard')
def dashboard():
    if not session.get('user_id'):
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    
    # Récupération des vendeurs depuis OpenCVE
    vendors = opencve_session.execute(
        text("SELECT * FROM opencve_vendors ORDER BY name LIMIT 50")
    ).fetchall()

    # Récupération des CVEs
    cves = opencve_session.execute(text("""
        SELECT cve_id, title, created_at, metrics
        FROM opencve_cves
        ORDER BY created_at DESC
        LIMIT 10
    """)).fetchall()

    return render_template('dashboard.html', user=user, vendors=vendors, cves=cves)

@app.route('/api/cves')
def get_cves():
    vendor = request.args.get('vendor', None)
    
    query = """
        SELECT cve_id, title, created_at, metrics
        FROM opencve_cves
        {vendor_filter}
        ORDER BY created_at DESC
        LIMIT 100
    """
    
    params = {}
    if vendor:
        query = query.format(vendor_filter="WHERE cve_id IN (SELECT cve_id FROM opencve_cve_vendors WHERE vendor_id = :vendor_id)")
        vendor_id = opencve_session.execute(
            text("SELECT id FROM opencve_vendors WHERE name = :name"),
            {'name': vendor}
        ).scalar()
        params['vendor_id'] = vendor_id
    else:
        query = query.format(vendor_filter="")
    
    result = opencve_session.execute(text(query), params).fetchall()

    return jsonify([
        {
            'id': row.cve_id,
            'title': row.title or '',
            'date': row.created_at.strftime('%Y-%m-%d') if row.created_at else '',
            'cvss_score': row.metrics.get('cvss2', {}).get('score') if row.metrics else None,
            'cvss_vector': row.metrics.get('cvss2', {}).get('vector') if row.metrics else None,
            'link': f"https://www.opencve.io/cve/{row.cve_id}",
        } for row in result
    ])

@app.route('/search_vendors')
def search_vendors():
    if not session.get('user_id'):
        return redirect(url_for('login'))
    
    query = request.args.get('query', '')
    
    vendors = opencve_session.execute(
        text("SELECT * FROM opencve_vendors WHERE name ILIKE :query ORDER BY name "),
        {'query': f'%{query}%'}
    ).fetchall()
    
    return render_template('vendor_results.html', vendors=vendors, query=query)

@app.route('/update_notification', methods=['POST'])
def update_notification():
    if not session.get('user_id'):
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    user.frequence = request.form['frequence']
    db.session.commit()
    return redirect(url_for('dashboard'))

# Création des tables locales SQLite
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)