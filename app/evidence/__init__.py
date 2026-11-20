from flask import Blueprint
evidence_bp = Blueprint('evidence', __name__)
from app.evidence import routes  # noqa: F401, E402
