from .. import db
from flask_login import UserMixin
from ..Crypto import encrypt_data, decrypt_data  # 👈 Import mis à jour

class Subscriber(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    _email = db.Column("email", db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    vendors = db.Column(db.Text)
    role = db.Column(db.String(50), default='user')
    twofa_secret = db.Column(db.String(255), nullable=True)

    @property
    def email(self):
        return decrypt_data(self._email)

    @email.setter
    def email(self, value):
        self._email = encrypt_data(value)
