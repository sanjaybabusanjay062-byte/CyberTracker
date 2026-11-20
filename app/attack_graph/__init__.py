from flask import Blueprint
attack_graph_bp = Blueprint('attack_graph', __name__)
from app.attack_graph import routes  # noqa: F401, E402
