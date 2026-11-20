from flask import Blueprint
ai_bp = Blueprint('ai_assistant', __name__)
from app.ai_assistant import routes  # noqa: F401, E402
