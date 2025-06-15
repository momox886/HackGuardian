from .. import db
from datetime import datetime

class CriticalCvePushed(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cve_id = db.Column(db.String(100), nullable=False)
    vendor = db.Column(db.String(100), nullable=False)
    pushed_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint('cve_id', 'vendor', name='unique_cve_ws_push'),
    )
