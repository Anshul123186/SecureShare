from flask import request

from extensions import db
from models import AuditLog


def log_event(event_type: str, description: str, user=None, file=None) -> None:
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    log = AuditLog(
        user=user,
        ip_address=ip,
        event_type=event_type,
        description=description,
    )
    db.session.add(log)
    db.session.commit()

