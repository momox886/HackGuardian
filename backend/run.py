from app import create_app, db, socketio
from app.models import Subscriber
from werkzeug.security import generate_password_hash
import os
from dotenv import load_dotenv

load_dotenv()

app = create_app()

with app.app_context():
    db.create_all()

    # Vérifie s'il existe déjà un superadmin avec cet email (déchiffré via @property)
    target_email = 'habibdiallo186@gmail.com'
    existing_users = Subscriber.query.all()
    if not any(u.email == target_email for u in existing_users):
        superadmin = Subscriber(
            email=target_email,
            password=generate_password_hash('1515F@timata'),
            role='superadmin',
            name='Diallo',            # 👈 Tu peux personnaliser
            first_name='Habib',
            organization='ISEN Méditerranée',
            vendors=''
        )
        db.session.add(superadmin)
        db.session.commit()
        print("✅ Superadmin créé.")
    else:
        print("ℹ️ Superadmin déjà existant.")

if __name__ == '__main__':
    import eventlet
    import eventlet.wsgi

    socketio.run(app, host='0.0.0.0', port=5000, debug=True)

