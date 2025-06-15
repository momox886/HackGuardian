from .. import db
from datetime import datetime

class CriticalCveSent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subscriber_email = db.Column(db.String(120), nullable=False)
    cve_id = db.Column(db.String(100), nullable=False)
    vendor = db.Column(db.String(100), nullable=False)
    sent_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint('subscriber_email', 'cve_id', 'vendor', name='unique_cve_sent'),
    )
