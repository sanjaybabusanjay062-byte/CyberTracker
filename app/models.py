import json
from datetime import datetime
from flask_login import UserMixin
from app import db


class User(db.Model, UserMixin):
    """System user model with role-based access control."""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(30), default='investigator', nullable=False)  # admin, investigator, viewer
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)

    # Relationships
    assigned_cases = db.relationship('Case', backref='investigator', lazy=True)
    evidences = db.relationship('Evidence', backref='uploader', lazy=True)
    authored_notes = db.relationship('CaseNote', backref='author', lazy=True)
    audit_logs = db.relationship('AuditLog', backref='user', lazy=True)

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'is_active': self.is_active
        }


class Case(db.Model):
    """Investigation case container."""
    __tablename__ = 'cases'

    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.String(50), unique=True, nullable=False, index=True)  # CT-2024-001
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(30), default='open', nullable=False)  # open, active, closed, archived
    priority = db.Column(db.String(30), default='medium', nullable=False)  # low, medium, high, critical
    investigator_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    closed_at = db.Column(db.DateTime, nullable=True)

    # Relationships
    evidence_items = db.relationship('Evidence', backref='case', lazy=True, cascade='all, delete-orphan')
    log_records = db.relationship('LogRecord', backref='case', lazy=True, cascade='all, delete-orphan')
    threat_alerts = db.relationship('ThreatAlert', backref='case', lazy=True, cascade='all, delete-orphan')
    notes = db.relationship('CaseNote', backref='case', lazy=True, cascade='all, delete-orphan', order_by='CaseNote.timestamp.desc()')

    def to_dict(self, include_counts=True):
        data = {
            'id': self.id,
            'case_id': self.case_id,
            'title': self.title,
            'description': self.description or '',
            'status': self.status,
            'priority': self.priority,
            'investigator_id': self.investigator_id,
            'investigator_name': self.investigator.username if self.investigator else 'Unassigned',
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'closed_at': self.closed_at.isoformat() if self.closed_at else None,
        }
        if include_counts:
            data['evidence_count'] = len(self.evidence_items)
            data['alert_count'] = len(self.threat_alerts)
            data['log_count'] = len(self.log_records)
            data['note_count'] = len(self.notes)
        return data


class Evidence(db.Model):
    """Digital evidence artifact with cryptographic hash verification."""
    __tablename__ = 'evidence'

    id = db.Column(db.Integer, primary_key=True)
    evidence_id = db.Column(db.String(50), unique=True, nullable=False, index=True)  # EV-001
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id'), nullable=False, index=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)  # in bytes
    file_type = db.Column(db.String(50), nullable=False)
    sha256_hash = db.Column(db.String(64), nullable=False)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    description = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(30), default='stored', nullable=False)  # stored, analyzed, archived, deleted
    integrity_verified = db.Column(db.Boolean, default=True, nullable=False)
    integrity_check_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    logs = db.relationship('LogRecord', backref='evidence', lazy=True, cascade='all, delete-orphan')
    alerts = db.relationship('ThreatAlert', backref='evidence', lazy=True, cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'id': self.id,
            'evidence_id': self.evidence_id,
            'case_id': self.case_id,
            'case_reference': self.case.case_id if self.case else None,
            'filename': self.filename,
            'original_filename': self.original_filename,
            'file_path': self.file_path,
            'file_size': self.file_size,
            'file_type': self.file_type,
            'sha256_hash': self.sha256_hash,
            'uploaded_by': self.uploaded_by,
            'uploader_name': self.uploader.username if self.uploader else 'Unknown',
            'uploaded_at': self.uploaded_at.isoformat() if self.uploaded_at else None,
            'description': self.description or '',
            'status': self.status,
            'integrity_verified': self.integrity_verified,
            'integrity_check_at': self.integrity_check_at.isoformat() if self.integrity_check_at else None,
            'parsed_logs_count': len(self.logs)
        }


class LogRecord(db.Model):
    """Normalized forensic log event."""
    __tablename__ = 'log_records'

    id = db.Column(db.Integer, primary_key=True)
    evidence_id = db.Column(db.Integer, db.ForeignKey('evidence.id'), nullable=True, index=True)
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id'), nullable=True, index=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    source_ip = db.Column(db.String(50), nullable=True, index=True)
    destination_ip = db.Column(db.String(50), nullable=True, index=True)
    username = db.Column(db.String(100), nullable=True, index=True)
    event_type = db.Column(db.String(50), nullable=False, index=True)  # login_success, login_failure, etc.
    event_description = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(20), default='info', nullable=False, index=True)  # info, low, medium, high, critical
    raw_log = db.Column(db.Text, nullable=True)
    parsed_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    is_suspicious = db.Column(db.Boolean, default=False, nullable=False, index=True)
    threat_category = db.Column(db.String(100), nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'evidence_id': self.evidence_id,
            'case_id': self.case_id,
            'case_ref': self.case.case_id if self.case else None,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'username': self.username,
            'event_type': self.event_type,
            'event_description': self.event_description,
            'severity': self.severity,
            'raw_log': self.raw_log,
            'parsed_at': self.parsed_at.isoformat() if self.parsed_at else None,
            'is_suspicious': self.is_suspicious,
            'threat_category': self.threat_category
        }


class ThreatAlert(db.Model):
    """Correlated threat alert flagged by automated detection rules or AI."""
    __tablename__ = 'threat_alerts'

    id = db.Column(db.Integer, primary_key=True)
    alert_id = db.Column(db.String(50), unique=True, nullable=False, index=True)
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id'), nullable=True, index=True)
    evidence_id = db.Column(db.Integer, db.ForeignKey('evidence.id'), nullable=True, index=True)
    alert_type = db.Column(db.String(100), nullable=False, index=True)
    severity = db.Column(db.String(20), nullable=False, index=True)  # low, medium, high, critical
    description = db.Column(db.Text, nullable=False)
    source_ip = db.Column(db.String(50), nullable=True, index=True)
    username = db.Column(db.String(100), nullable=True, index=True)
    timestamp = db.Column(db.DateTime, nullable=False, index=True)
    detected_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    status = db.Column(db.String(30), default='new', nullable=False)  # new, investigating, resolved, false_positive
    notes = db.Column(db.Text, nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'alert_id': self.alert_id,
            'case_id': self.case_id,
            'case_ref': self.case.case_id if self.case else None,
            'evidence_id': self.evidence_id,
            'alert_type': self.alert_type,
            'severity': self.severity,
            'description': self.description,
            'source_ip': self.source_ip,
            'username': self.username,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'detected_at': self.detected_at.isoformat() if self.detected_at else None,
            'status': self.status,
            'notes': self.notes or ''
        }


class ChatMessage(db.Model):
    """Conversation history for AI Assistant chat sessions."""
    __tablename__ = 'chat_messages'

    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(100), nullable=False, index=True)
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id'), nullable=True, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    role = db.Column(db.String(20), nullable=False)  # user, assistant
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    related_log_ids = db.Column(db.Text, nullable=True)  # JSON string list of log IDs

    def get_related_log_ids(self):
        if self.related_log_ids:
            try:
                return json.loads(self.related_log_ids)
            except Exception:
                return []
        return []

    def set_related_log_ids(self, ids_list):
        self.related_log_ids = json.dumps(ids_list) if ids_list else None

    def to_dict(self):
        return {
            'id': self.id,
            'session_id': self.session_id,
            'case_id': self.case_id,
            'user_id': self.user_id,
            'role': self.role,
            'content': self.content,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'related_log_ids': self.get_related_log_ids()
        }


class AuditLog(db.Model):
    """Security audit trail tracking user interactions and administrative actions."""
    __tablename__ = 'audit_logs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    action = db.Column(db.String(100), nullable=False, index=True)
    resource_type = db.Column(db.String(50), nullable=True)
    resource_id = db.Column(db.String(50), nullable=True)
    ip_address = db.Column(db.String(50), nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    details = db.Column(db.Text, nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'username': self.user.username if self.user else 'System',
            'action': self.action,
            'resource_type': self.resource_type,
            'resource_id': self.resource_id,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'details': self.details
        }


class CaseNote(db.Model):
    """Investigator notes, hypotheses, and collaboration items."""
    __tablename__ = 'case_notes'

    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id'), nullable=False, index=True)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    note_type = db.Column(db.String(50), default='general', nullable=False)  # general, finding, evidence_note, action_item

    def to_dict(self):
        return {
            'id': self.id,
            'case_id': self.case_id,
            'author_id': self.author_id,
            'author_name': self.author.username if self.author else 'Unknown',
            'content': self.content,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'note_type': self.note_type
        }
