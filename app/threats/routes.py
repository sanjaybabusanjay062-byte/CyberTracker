from flask import render_template, jsonify, request
from flask_login import login_required, current_user
from sqlalchemy import func
from app.threats import threats_bp
from app.models import ThreatAlert, LogRecord, Case, AuditLog
from app.utils.threat_detector import run_all_detections
from app import db


@threats_bp.route('/threats')
@login_required
def index():
    cases = Case.query.filter(Case.status != 'archived').all()
    return render_template('threats/index.html', title='Threat Detection', cases=cases)


@threats_bp.route('/api/threats/list')
@login_required
def list_threats():
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 50))
    case_id = request.args.get('case_id')
    severity = request.args.get('severity')
    alert_type = request.args.get('alert_type')
    status = request.args.get('status')

    q = ThreatAlert.query
    if case_id:
        q = q.filter(ThreatAlert.case_id == int(case_id))
    if severity:
        q = q.filter(ThreatAlert.severity == severity)
    if alert_type:
        q = q.filter(ThreatAlert.alert_type == alert_type)
    if status:
        q = q.filter(ThreatAlert.status == status)

    total = q.count()
    alerts = q.order_by(ThreatAlert.detected_at.desc()).offset((page - 1) * per_page).limit(per_page).all()

    return jsonify({
        'alerts': [a.to_dict() for a in alerts],
        'total': total,
        'page': page,
        'pages': (total + per_page - 1) // per_page
    })


@threats_bp.route('/api/threats/scan/<int:case_id>', methods=['POST'])
@login_required
def scan(case_id):
    case = Case.query.get_or_404(case_id)
    records = LogRecord.query.filter(LogRecord.case_id == case_id).all()

    if not records:
        return jsonify({'error': 'No log records found for this case. Upload and analyze evidence first.'}), 400

    record_dicts = [r.to_dict() for r in records]
    new_alerts = run_all_detections(record_dicts, case_id=case_id)

    created = 0
    for alert_data in new_alerts:
        existing = ThreatAlert.query.filter_by(alert_id=alert_data['alert_id']).first()
        if not existing:
            alert = ThreatAlert(
                alert_id=alert_data['alert_id'],
                case_id=case_id,
                evidence_id=alert_data.get('evidence_id'),
                alert_type=alert_data['alert_type'],
                severity=alert_data['severity'],
                description=alert_data['description'],
                source_ip=alert_data.get('source_ip'),
                username=alert_data.get('username'),
                timestamp=alert_data.get('timestamp'),
                status='new'
            )
            db.session.add(alert)
            created += 1

    audit = AuditLog(
        user_id=current_user.id,
        action='THREAT_SCAN',
        resource_type='case',
        resource_id=str(case_id),
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent', '')[:255],
        details=f'Threat scan on case {case.case_id}: {created} new alerts found'
    )
    db.session.add(audit)
    db.session.commit()

    return jsonify({
        'success': True,
        'alerts_created': created,
        'total_analyzed': len(records),
        'message': f'Scan complete. {created} new threat alerts detected from {len(records)} log records.'
    })


@threats_bp.route('/api/threats/stats')
@login_required
def stats():
    case_id = request.args.get('case_id')
    q = ThreatAlert.query
    if case_id:
        q = q.filter(ThreatAlert.case_id == int(case_id))

    total = q.count()
    by_severity = db.session.query(
        ThreatAlert.severity, func.count(ThreatAlert.id)
    ).group_by(ThreatAlert.severity).all()
    by_type = db.session.query(
        ThreatAlert.alert_type, func.count(ThreatAlert.id)
    ).group_by(ThreatAlert.alert_type).all()
    investigating = q.filter(ThreatAlert.status == 'investigating').count()

    return jsonify({
        'total': total,
        'investigating': investigating,
        'by_severity': {s: c for s, c in by_severity},
        'by_type': {t: c for t, c in by_type}
    })


@threats_bp.route('/api/threats/<int:alert_id>/status', methods=['PATCH'])
@login_required
def update_status(alert_id):
    alert = ThreatAlert.query.get_or_404(alert_id)
    data = request.get_json() or {}
    new_status = data.get('status')
    if new_status not in ('new', 'investigating', 'resolved', 'false_positive'):
        return jsonify({'error': 'Invalid status value'}), 400

    alert.status = new_status
    if data.get('notes'):
        alert.notes = data['notes']

    audit = AuditLog(
        user_id=current_user.id,
        action='ALERT_STATUS_UPDATE',
        resource_type='threat_alert',
        resource_id=alert.alert_id,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent', '')[:255],
        details=f'Status updated to {new_status}'
    )
    db.session.add(audit)
    db.session.commit()
    return jsonify({'success': True, 'alert': alert.to_dict()})
