import os
from dotenv import load_dotenv

BASE_DIR = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
load_dotenv(os.path.join(BASE_DIR, '.env'))


class Config:
    """CyberTrace AI configuration settings."""

    # Security & Core
    SECRET_KEY = os.environ.get('SECRET_KEY', 'cybertrace-ai-insecure-secret-key-2024')
    DEBUG = os.environ.get('DEBUG', 'False').lower() in ('true', '1', 't')

    # Database
    db_url = os.environ.get('DATABASE_URL', f"sqlite:///{os.path.join(BASE_DIR, 'cybertrace.db')}")
    if db_url.startswith('sqlite:///') and not os.path.isabs(db_url.replace('sqlite:///', '')):
        rel_path = db_url.replace('sqlite:///', '')
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{os.path.join(BASE_DIR, rel_path)}"
    else:
        SQLALCHEMY_DATABASE_URI = db_url
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # File Storage
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', os.path.join(BASE_DIR, 'uploads'))
    REPORTS_FOLDER = os.environ.get('REPORTS_FOLDER', os.path.join(BASE_DIR, 'reports'))
    MAX_CONTENT_LENGTH = int(os.environ.get('MAX_UPLOAD_SIZE_MB', 50)) * 1024 * 1024
    ALLOWED_EXTENSIONS = {'csv', 'json', 'txt', 'log', 'pcap', 'xml'}

    # Forms & Session Security
    WTF_CSRF_ENABLED = os.environ.get('WTF_CSRF_ENABLED', 'True').lower() in ('true', '1', 't')
    WTF_CSRF_CHECK_DEFAULT = False  # Let manual CSRF protect traditional forms while REST APIs use tokens or exemption
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_COOKIE_SECURE = False  # Set to True in HTTPS production

    # AI Integration Settings
    AI_API_KEY = os.environ.get('AI_API_KEY', '')
    AI_MODE = os.environ.get('AI_MODE', 'rule_based')  # 'rule_based' or 'llm'
