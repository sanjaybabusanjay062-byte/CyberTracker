from flask import Blueprint
cases_bp = Blueprint('cases', __name__)
from app.cases import routes  # noqa: F401, E402
