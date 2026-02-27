from flask import Blueprint, render_template, abort
from flask_login import login_required, current_user

from models import User, AuditLog


admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


def _require_admin():
    if not current_user.is_authenticated or not current_user.is_admin:
        abort(403)


@admin_bp.before_request
def before_request():
    _require_admin()


@admin_bp.route("/dashboard")
@login_required
def dashboard():
    users = User.query.order_by(User.created_at.desc()).all()
    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(200).all()
    return render_template("admin_dashboard.html", users=users, logs=logs)

