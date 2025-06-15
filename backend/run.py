import socket
from app import create_app, db, socketio
from app.models.subscriber import Subscriber
from werkzeug.security import generate_password_hash
import os
from dotenv import load_dotenv

load_dotenv()

# Étape 1 : Créer l'application
app = create_app()
mdp = os.getenv("PASSWORD")

# Étape 2 : Initialiser la base de données et le superadmin
with app.app_context():
    db.create_all()

    if not Subscriber.query.filter_by(email='habibdiallo186@gmail.com').first():
        superadmin = Subscriber(
            email='habibdiallo186@gmail.com',
            password=generate_password_hash('1515F@timata'),
            role='superadmin'
        )
        db.session.add(superadmin)
        db.session.commit()
        print("✅ Superadmin créé")


# Étape 3 : Trouver l'adresse IP locale de la machine
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Connexion "fictive" pour déterminer l'IP locale
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP


# Étape 4 : Lancer le serveur sur l'adresse IP locale
if __name__ == '__main__':
    local_ip = get_local_ip()
    print(f"🚀 Lancement du serveur sur http://{local_ip}:5000")

    # Lancer avec eventlet si tu l'utilises, sinon tu peux utiliser juste socketio.run
    import eventlet
    import eventlet.wsgi

    socketio.run(app, host=local_ip, port=5000, debug=True)
