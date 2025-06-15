from flask_login import UserMixin
from .. import db

# models.py
class Subscriber(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    vendors = db.Column(db.Text, default='')
    role = db.Column(db.String(50), default='user')  # 'user', 'admin', 'superadmin'


    def get_id(self):
        return str(self.id)
