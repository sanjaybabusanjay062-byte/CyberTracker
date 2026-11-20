from flask import Blueprint
logs_bp = Blueprint('logs', __name__)
from app.logs import routes  # noqa: F401, E402
