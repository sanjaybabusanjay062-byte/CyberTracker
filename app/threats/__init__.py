from flask import Blueprint
threats_bp = Blueprint('threats', __name__)
from app.threats import routes  # noqa: F401, E402
