# decorators.py
from functools import wraps
from flask import abort, flash, redirect, render_template, request, url_for
from flask_login import current_user

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role not in ['admin', 'superadmin']:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def superadmin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'superadmin':
            abort(403)
        if not current_user.twofa_secret:
            flash("2FA requis pour accéder à cette page.", "danger")
            return redirect(url_for('main.enable_2fa'))
        return f(*args, **kwargs)
    return decorated_function

