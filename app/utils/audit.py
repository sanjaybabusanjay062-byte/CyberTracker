from datetime import datetime
from flask import request
from flask_login import current_user
from app import db
from app.models import AuditLog


def log_audit(action, resource_type=None, resource_id=None, details=None, user_id=None):
    """Record an action in the system audit log."""
    try:
        uid = user_id
        if uid is None and current_user and current_user.is_authenticated:
            uid = current_user.id

        ip = request.remote_addr if request else '127.0.0.1'
        ua = request.headers.get('User-Agent', '')[:250] if request else 'Internal System'

        log_entry = AuditLog(
            user_id=uid,
            action=action,
            resource_type=resource_type,
            resource_id=str(resource_id) if resource_id is not None else None,
            ip_address=ip,
            user_agent=ua,
            timestamp=datetime.utcnow(),
            details=details
        )
        db.session.add(log_entry)
        db.session.commit()
    except Exception:
        db.session.rollback()
