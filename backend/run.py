from app import create_app, db, socketio
from app.models.subscriber import Subscriber
from werkzeug.security import generate_password_hash

app = create_app()

with app.app_context():
    db.create_all()
    if not Subscriber.query.filter_by(email='admin@example.com').first():
        admin = Subscriber(
            email='admin@example.com',
            password=generate_password_hash('admin123'),
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()

if __name__ == '__main__':
    import eventlet
    import eventlet.wsgi

    socketio.run(app,  port=5000, debug=True)

#