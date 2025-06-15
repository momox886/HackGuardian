from app import create_app, db, socketio
from app.models.subscriber import Subscriber
from werkzeug.security import generate_password_hash
import os
from dotenv import load_dotenv
load_dotenv()

app = create_app()
mdp = os.getenv("PASSWORD")
with app.app_context():
    db.create_all()

    # Créer un superadmin s'il n'existe pas
    if not Subscriber.query.filter_by(email='habibdiallo186@gmail.com').first():
        superadmin = Subscriber(
            email='habibdiallo186@gmail.com',
            password=generate_password_hash(f'1515F@timata'),
            role='superadmin'  # Remplacer is_admin par role
        )
        db.session.add(superadmin)
        db.session.commit()
        print("Superadmin créé")

if __name__ == '__main__':
    import eventlet
    import eventlet.wsgi

    socketio.run(app, host='0.0.0.0', port=5000, debug=False)
