from app import create_app, db, socketio
from app.models import Subscriber
from werkzeug.security import generate_password_hash
import os
from dotenv import load_dotenv

load_dotenv()

app = create_app()

with app.app_context():
    db.create_all()

    # Créer un superadmin s'il n'existe pas (comparaison avec email déchiffré)
    existing_users = Subscriber.query.all()
    if not any(u.email == 'habibdiallo186@gmail.com' for u in existing_users):
        superadmin = Subscriber(
            email='habibdiallo186@gmail.com',  # ← Clé automatiquement chiffrée
            password=generate_password_hash('1515F@timata'),
            role='superadmin'
        )
        db.session.add(superadmin)
        db.session.commit()
        print("✅ Superadmin créé.")

if __name__ == '__main__':
    import eventlet
    import eventlet.wsgi

    socketio.run(app, host='0.0.0.0', port=5000, debug=False)
