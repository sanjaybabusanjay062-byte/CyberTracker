import os
from flask import Flask, jsonify, render_template, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from app.config import Config

db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()


def create_app(config_class=Config):
    """Application factory for CYBERTRACE AI."""
    base_dir = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
    template_dir = os.path.join(base_dir, 'templates')
    static_dir = os.path.join(base_dir, 'static')
    app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)
    app.config.from_object(config_class)

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)

    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'warning'

    # Ensure required directories exist
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(app.config['REPORTS_FOLDER'], exist_ok=True)

    # User loader callback for Flask-Login
    from app.models import User

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    # Register blueprints
    from app.auth.routes import auth_bp
    from app.dashboard.routes import dashboard_bp
    from app.evidence.routes import evidence_bp
    from app.logs.routes import logs_bp
    from app.ai_assistant.routes import ai_bp
    from app.timeline.routes import timeline_bp
    from app.attack_graph.routes import attack_graph_bp
    from app.threats.routes import threats_bp
    from app.cases.routes import cases_bp
    from app.reports.routes import reports_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(evidence_bp)
    app.register_blueprint(logs_bp)
    app.register_blueprint(ai_bp)
    app.register_blueprint(timeline_bp)
    app.register_blueprint(attack_graph_bp)
    app.register_blueprint(threats_bp)
    app.register_blueprint(cases_bp)
    app.register_blueprint(reports_bp)

    # Exempt API endpoints from CSRF for seamless JSON REST calls
    csrf.exempt(evidence_bp)
    csrf.exempt(logs_bp)
    csrf.exempt(ai_bp)
    csrf.exempt(cases_bp)
    csrf.exempt(threats_bp)
    csrf.exempt(reports_bp)
    csrf.exempt(timeline_bp)
    csrf.exempt(attack_graph_bp)

    # Register global error handlers
    @app.errorhandler(404)
    def not_found_error(error):
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Resource not found', 'status_code': 404}), 404
        return render_template('errors/404.html'), 404

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Internal server error', 'status_code': 500}), 500
        return render_template('errors/500.html'), 500

    return app
