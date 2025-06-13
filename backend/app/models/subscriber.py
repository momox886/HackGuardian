from flask_login import UserMixin
from .. import db

class Subscriber(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    vendors = db.Column(db.Text, default="")  # Liste des vendeurs suivis (séparés par virgule)

    def get_id(self):
        return str(self.id)
