import os
import uuid
from flask import render_template, jsonify, request, current_app
from flask_login import login_required, current_user
from datetime import datetime
from werkzeug.utils import secure_filename
from app.evidence import evidence_bp
from app.models import Evidence, Case, AuditLog
from app.utils.hashing import compute_sha256, verify_integrity
from app.utils.log_parser import parse_log_file, detect_format
from app.models import LogRecord
from app import db


def allowed_file(filename):
    allowed = current_app.config.get('ALLOWED_EXTENSIONS', {'csv', 'json', 'txt', 'log', 'xml'})
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed


def generate_evidence_id():
    count = Evidence.query.count()
    return f'EV-{count + 1:04d}'


@evidence_bp.route('/evidence')
@login_required
def index():
    cases = Case.query.filter(Case.status != 'archived').all()
    return render_template('evidence/index.html', title='Evidence Management', cases=cases)


@evidence_bp.route('/api/evidence/upload', methods=['POST'])
@login_required
def upload():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part in request'}), 400

    file = request.files['file']
    case_id = request.form.get('case_id')
    description = request.form.get('description', '')

    if not file or file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    if not allowed_file(file.filename):
        return jsonify({'error': 'File type not allowed. Supported: CSV, JSON, TXT, LOG, XML'}), 400
    if not case_id:
        return jsonify({'error': 'Case ID is required'}), 400

    case = Case.query.get(case_id)
    if not case:
        return jsonify({'error': 'Case not found'}), 404

    original_filename = file.filename
    safe_name = secure_filename(original_filename)
    evidence_id = generate_evidence_id()

    # Create subdirectory per evidence item
    evidence_dir = os.path.join(current_app.config['UPLOAD_FOLDER'], evidence_id)
    os.makedirs(evidence_dir, exist_ok=True)

    file_path = os.path.join(evidence_dir, safe_name)
    file.save(file_path)

    file_size = os.path.getsize(file_path)
    sha256 = compute_sha256(file_path)
    file_ext = safe_name.rsplit('.', 1)[-1].lower() if '.' in safe_name else 'unknown'

    ev = Evidence(
        evidence_id=evidence_id,
        case_id=int(case_id),
        filename=safe_name,
        original_filename=original_filename,
        file_path=file_path,
        file_size=file_size,
        file_type=file_ext,
        sha256_hash=sha256,
        uploaded_by=current_user.id,
        description=description,
        status='stored',
        integrity_verified=True,
        integrity_check_at=datetime.utcnow()
    )
    db.session.add(ev)

    audit = AuditLog(
        user_id=current_user.id,
        action='EVIDENCE_UPLOADED',
        resource_type='evidence',
        resource_id=evidence_id,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent', '')[:255],
        details=f'Uploaded {original_filename} ({file_size} bytes) SHA256:{sha256}'
    )
    db.session.add(audit)
    db.session.commit()

    return jsonify({'success': True, 'evidence': ev.to_dict()}), 201


@evidence_bp.route('/api/evidence/list')
@login_required
def list_evidence():
    case_id = request.args.get('case_id')
    file_type = request.args.get('file_type')
    status = request.args.get('status')

    q = Evidence.query.filter(Evidence.status != 'deleted')
    if case_id:
        q = q.filter(Evidence.case_id == int(case_id))
    if file_type:
        q = q.filter(Evidence.file_type == file_type)
    if status:
        q = q.filter(Evidence.status == status)

    items = q.order_by(Evidence.uploaded_at.desc()).all()
    return jsonify({'evidence': [e.to_dict() for e in items], 'total': len(items)})


@evidence_bp.route('/api/evidence/<int:ev_id>')
@login_required
def get_evidence(ev_id):
    ev = Evidence.query.get_or_404(ev_id)
    return jsonify(ev.to_dict())


@evidence_bp.route('/api/evidence/<int:ev_id>', methods=['DELETE'])
@login_required
def delete_evidence(ev_id):
    ev = Evidence.query.get_or_404(ev_id)
    ev.status = 'deleted'
    audit = AuditLog(
        user_id=current_user.id,
        action='EVIDENCE_DELETED',
        resource_type='evidence',
        resource_id=ev.evidence_id,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent', '')[:255]
    )
    db.session.add(audit)
    db.session.commit()
    return jsonify({'success': True, 'message': 'Evidence removed'})


@evidence_bp.route('/api/evidence/<int:ev_id>/verify', methods=['POST'])
@login_required
def verify(ev_id):
    ev = Evidence.query.get_or_404(ev_id)
    if not os.path.exists(ev.file_path):
        return jsonify({'success': False, 'error': 'File not found on disk', 'integrity': False}), 404

    intact, current_hash = verify_integrity(ev.file_path, ev.sha256_hash)
    ev.integrity_verified = intact
    ev.integrity_check_at = datetime.utcnow()

    audit = AuditLog(
        user_id=current_user.id,
        action='INTEGRITY_CHECK',
        resource_type='evidence',
        resource_id=ev.evidence_id,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent', '')[:255],
        details=f'Integrity {"OK" if intact else "FAILED"}. Current hash: {current_hash}'
    )
    db.session.add(audit)
    db.session.commit()

    return jsonify({
        'success': True,
        'integrity': intact,
        'stored_hash': ev.sha256_hash,
        'current_hash': current_hash,
        'message': 'File integrity verified — hash matches.' if intact else 'INTEGRITY VIOLATION — file has been modified!'
    })


@evidence_bp.route('/api/evidence/<int:ev_id>/analyze', methods=['POST'])
@login_required
def analyze(ev_id):
    ev = Evidence.query.get_or_404(ev_id)
    if not os.path.exists(ev.file_path):
        return jsonify({'error': 'File not found on disk'}), 404

    try:
        records = parse_log_file(ev.file_path)
        count = 0
        for rec in records:
            lr = LogRecord(
                evidence_id=ev.id,
                case_id=ev.case_id,
                timestamp=rec.get('timestamp', datetime.utcnow()),
                source_ip=rec.get('source_ip'),
                destination_ip=rec.get('destination_ip'),
                username=rec.get('username'),
                event_type=rec.get('event_type', 'unknown'),
                event_description=rec.get('event_description', ''),
                severity=rec.get('severity', 'info'),
                raw_log=rec.get('raw_log', ''),
                is_suspicious=rec.get('is_suspicious', False),
                threat_category=rec.get('threat_category')
            )
            db.session.add(lr)
            count += 1

        ev.status = 'analyzed'
        audit = AuditLog(
            user_id=current_user.id,
            action='EVIDENCE_ANALYZED',
            resource_type='evidence',
            resource_id=ev.evidence_id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', '')[:255],
            details=f'Parsed {count} log records from {ev.filename}'
        )
        db.session.add(audit)
        db.session.commit()
        return jsonify({'success': True, 'records_parsed': count, 'message': f'Successfully parsed {count} log records.'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to parse file: {str(e)}'}), 500
