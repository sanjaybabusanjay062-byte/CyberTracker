import csv
import io
from flask import render_template, jsonify, request, Response
from flask_login import login_required, current_user
from datetime import datetime
from sqlalchemy import or_, func
from app.logs import logs_bp
from app.models import LogRecord, Evidence, Case, AuditLog
from app.utils.log_parser import parse_log_file
from app import db


@logs_bp.route('/logs')
@login_required
def index():
    cases = Case.query.filter(Case.status != 'archived').all()
    evidence_items = Evidence.query.filter(Evidence.status != 'deleted').all()
    return render_template('logs/index.html', title='Log Analysis', cases=cases, evidence_items=evidence_items)


@logs_bp.route('/api/logs/list')
@login_required
def list_logs():
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 50))
    case_id = request.args.get('case_id')
    event_type = request.args.get('event_type')
    severity = request.args.get('severity')
    search = request.args.get('search', '')
    source_ip = request.args.get('source_ip', '')
    username = request.args.get('username', '')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    q = LogRecord.query
    if case_id:
        q = q.filter(LogRecord.case_id == int(case_id))
    if event_type:
        q = q.filter(LogRecord.event_type == event_type)
    if severity:
        q = q.filter(LogRecord.severity == severity)
    if source_ip:
        q = q.filter(LogRecord.source_ip.ilike(f'%{source_ip}%'))
    if username:
        q = q.filter(LogRecord.username.ilike(f'%{username}%'))
    if search:
        q = q.filter(or_(
            LogRecord.event_description.ilike(f'%{search}%'),
            LogRecord.raw_log.ilike(f'%{search}%'),
            LogRecord.source_ip.ilike(f'%{search}%'),
            LogRecord.username.ilike(f'%{search}%')
        ))
    if start_date:
        q = q.filter(LogRecord.timestamp >= datetime.fromisoformat(start_date))
    if end_date:
        q = q.filter(LogRecord.timestamp <= datetime.fromisoformat(end_date))

    q = q.order_by(LogRecord.timestamp.desc())
    total = q.count()
    records = q.offset((page - 1) * per_page).limit(per_page).all()

    return jsonify({
        'logs': [r.to_dict() for r in records],
        'total': total,
        'page': page,
        'per_page': per_page,
        'pages': (total + per_page - 1) // per_page
    })


@logs_bp.route('/api/logs/stats')
@login_required
def log_stats():
    case_id = request.args.get('case_id')
    q = LogRecord.query
    if case_id:
        q = q.filter(LogRecord.case_id == int(case_id))

    total = q.count()
    suspicious = q.filter(LogRecord.is_suspicious == True).count()
    failed_logins = q.filter(LogRecord.event_type == 'login_failure').count()
    critical = q.filter(LogRecord.severity == 'critical').count()

    by_type = db.session.query(
        LogRecord.event_type, func.count(LogRecord.id)
    ).group_by(LogRecord.event_type).all()

    by_severity = db.session.query(
        LogRecord.severity, func.count(LogRecord.id)
    ).group_by(LogRecord.severity).all()

    return jsonify({
        'total': total,
        'suspicious': suspicious,
        'failed_logins': failed_logins,
        'critical': critical,
        'by_type': {t: c for t, c in by_type},
        'by_severity': {s: c for s, c in by_severity}
    })


@logs_bp.route('/api/logs/export')
@login_required
def export_logs():
    case_id = request.args.get('case_id')
    severity = request.args.get('severity')
    event_type = request.args.get('event_type')

    q = LogRecord.query
    if case_id:
        q = q.filter(LogRecord.case_id == int(case_id))
    if severity:
        q = q.filter(LogRecord.severity == severity)
    if event_type:
        q = q.filter(LogRecord.event_type == event_type)

    records = q.order_by(LogRecord.timestamp.desc()).limit(5000).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Timestamp', 'Source IP', 'Username', 'Event Type',
                     'Description', 'Severity', 'Is Suspicious', 'Case ID'])
    for r in records:
        writer.writerow([
            r.id,
            r.timestamp.isoformat() if r.timestamp else '',
            r.source_ip or '',
            r.username or '',
            r.event_type,
            r.event_description,
            r.severity,
            r.is_suspicious,
            r.case_id
        ])

    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=cybertrace_logs_export.csv'}
    )


@logs_bp.route('/api/logs/parse/<int:evidence_id>', methods=['POST'])
@login_required
def parse_evidence(evidence_id):
    from app.models import Evidence
    import os
    ev = Evidence.query.get_or_404(evidence_id)
    if not os.path.exists(ev.file_path):
        return jsonify({'error': 'File not found'}), 404
    try:
        records = parse_log_file(ev.file_path)
        count = 0
        for rec in records:
            lr = LogRecord(
                evidence_id=ev.id,
                case_id=ev.case_id,
                timestamp=rec.get('timestamp', datetime.utcnow()),
                source_ip=rec.get('source_ip'),
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
        db.session.commit()
        return jsonify({'success': True, 'records_parsed': count})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
