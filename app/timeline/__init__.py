from flask import Blueprint
timeline_bp = Blueprint('timeline', __name__)
from app.timeline import routes  # noqa: F401, E402
