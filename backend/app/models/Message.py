from datetime import datetime
from .. import db

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('subscriber.id'), nullable=False)
    sender_email = db.Column(db.String(120))
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    room = db.Column(db.String(100), nullable=False)  # Ex: 'admin' ou user_id
    is_read = db.Column(db.Boolean, default=False)
