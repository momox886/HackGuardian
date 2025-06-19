from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_socketio import SocketIO
from dotenv import load_dotenv
from datetime import datetime  # ✅ Ajout
load_dotenv()

db = SQLAlchemy()
login_manager = LoginManager()
socketio = SocketIO()

# ✅ Fonction utilitaire pour formatter une date en sécurité
def format_date_safe(value, fmt="%Y-%m-%d"):
    try:
        if isinstance(value, str):
            # Gestion du format ISO 8601 avec 'Z'
            value = value.replace("Z", "")
            value = datetime.fromisoformat(value)
        if isinstance(value, datetime):
            return value.strftime(fmt)
    except Exception:
        pass
    return ""

def create_app():
    from .routes import main
    from .models.subscriber import Subscriber
    from .commands import send_weekly

    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'votre_cle_secrete'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)
    login_manager.init_app(app)
    socketio.init_app(app)

    login_manager.login_view = 'main.login'

    @login_manager.user_loader
    def load_user(user_id):
        return Subscriber.query.get(int(user_id))

    app.register_blueprint(main)

    # ✅ Ajout du filtre de formatage date
    app.jinja_env.filters['format_date_safe'] = format_date_safe

    # 🔧 Enregistrement de la commande CLI
    app.cli.add_command(send_weekly)

    return app
