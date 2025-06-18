# app/models/message.py
from datetime import datetime
from .. import db
from ..Crypto import encrypt_data, decrypt_data

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('subscriber.id'), nullable=False)
    _sender_email = db.Column("sender_email", db.String(256))  # Champ chiffré
    _content = db.Column("content", db.Text, nullable=False)   # Champ chiffré
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    room = db.Column(db.String(100), nullable=False)
    is_read = db.Column(db.Boolean, default=False)

    @property
    def sender_email(self):
        try:
            return decrypt_data(self._sender_email)
        except Exception:
            return "[Erreur de déchiffrement]"

    @sender_email.setter
    def sender_email(self, value):
        self._sender_email = encrypt_data(value)

    @property
    def content(self):
        try:
            return decrypt_data(self._content)
        except Exception:
            return "[Erreur de déchiffrement]"

    @content.setter
    def content(self, value):
        self._content = encrypt_data(value)
