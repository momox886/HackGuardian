from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_socketio import SocketIO

db = SQLAlchemy()
login_manager = LoginManager()
socketio = SocketIO()  # ← Ajout de SocketIO

def create_app():
    from .routes import main
    from .models.subscriber import Subscriber

    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'votre_cle_secrete'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)
    login_manager.init_app(app)
    socketio.init_app(app)  # ← Initialisation SocketIO

    login_manager.login_view = 'main.login'

    @login_manager.user_loader
    def load_user(user_id):
        return Subscriber.query.get(int(user_id))

    app.register_blueprint(main)

    return app
