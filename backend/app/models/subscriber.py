from .. import db
from flask_login import UserMixin
from ..Crypto import encrypt_data, decrypt_data  # 👈 Import correct

class Subscriber(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    _name = db.Column("name", db.String(255), nullable=False)
    _first_name = db.Column("first_name", db.String(255), nullable=False)
    _email = db.Column("email", db.String(255), unique=True, nullable=False)
    _organization = db.Column("organization", db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    _vendors = db.Column("vendors", db.Text)  # Chiffré
    role = db.Column(db.String(50), default='user')
    frequence = db.Column(db.String(20), default='quotidien')  # ou 'hebdomadaire'
    twofa_secret = db.Column(db.String(255), nullable=True)

    # Email
    @property
    def email(self):
        try:
            return decrypt_data(self._email)
        except Exception:
            return "[Erreur email]"

    @email.setter
    def email(self, value):
        self._email = encrypt_data(value)

    # Nom
    @property
    def name(self):
        try:
            return decrypt_data(self._name)
        except Exception:
            return "[Erreur nom]"

    @name.setter
    def name(self, value):
        self._name = encrypt_data(value)

    # Prénom
    @property
    def first_name(self):
        try:
            return decrypt_data(self._first_name)
        except Exception:
            return "[Erreur prénom]"

    @first_name.setter
    def first_name(self, value):
        self._first_name = encrypt_data(value)

    # Organisation
    @property
    def organization(self):
        try:
            return decrypt_data(self._organization)
        except Exception:
            return "[Erreur organisation]"

    @organization.setter
    def organization(self, value):
        self._organization = encrypt_data(value)

    # Vendors
    @property
    def vendors(self):
        try:
            return decrypt_data(self._vendors) if self._vendors else ""
        except Exception:
            return "[Erreur vendors]"

    @vendors.setter
    def vendors(self, value):
        self._vendors = encrypt_data(value)

    # ✅ Liste des vendeurs déchiffrés
    def get_vendors_list(self):
        try:
            return [v.strip() for v in self.vendors.split(',') if v.strip()]
        except Exception:
            return []

    def set_vendors_list(self, vendor_list):
        try:
            cleaned = [v.strip() for v in vendor_list if v.strip()]
            self.vendors = ','.join(cleaned)
        except Exception:
            pass  # Gérer ou logger si nécessaire
