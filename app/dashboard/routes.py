from flask import render_template, jsonify
from flask_login import login_required, current_user
from datetime import datetime, timedelta
from sqlalchemy import func
from app.dashboard import dashboard_bp
from app.models import Case, Evidence, LogRecord, ThreatAlert, AuditLog
from app import db


@dashboard_bp.route('/')
@dashboard_bp.route('/dashboard')
@login_required
def index():
    return render_template('dashboard/index.html', title='Dashboard')


@dashboard_bp.route('/api/dashboard/stats')
@login_required
def stats():
    total_cases = Case.query.filter(Case.status != 'archived').count()
    open_cases = Case.query.filter(Case.status.in_(['open', 'active'])).count()
    total_evidence = Evidence.query.filter(Evidence.status != 'deleted').count()
    total_logs = LogRecord.query.count()
    threat_alerts = ThreatAlert.query.filter(ThreatAlert.status.in_(['new', 'investigating'])).count()
    critical_events = LogRecord.query.filter(LogRecord.severity == 'critical').count()
    suspicious_events = LogRecord.query.filter(LogRecord.is_suspicious == True).count()

    return jsonify({
        'total_cases': total_cases,
        'open_cases': open_cases,
        'total_evidence': total_evidence,
        'total_logs': total_logs,
        'threat_alerts': threat_alerts,
        'critical_events': critical_events,
        'suspicious_events': suspicious_events
    })


@dashboard_bp.route('/api/dashboard/recent-activity')
@login_required
def recent_activity():
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(10).all()
    return jsonify({'activities': [l.to_dict() for l in logs]})


@dashboard_bp.route('/api/dashboard/threat-severity')
@login_required
def threat_severity():
    results = db.session.query(
        ThreatAlert.severity, func.count(ThreatAlert.id)
    ).group_by(ThreatAlert.severity).all()

    labels = []
    counts = []
    colors = {
        'critical': '#ff4757',
        'high': '#ffa502',
        'medium': '#ffd32a',
        'low': '#00d4ff',
        'info': '#8892a4'
    }
    chart_colors = []

    for severity, count in results:
        labels.append(severity.capitalize())
        counts.append(count)
        chart_colors.append(colors.get(severity, '#8892a4'))

    if not labels:
        labels = ['No Alerts']
        counts = [1]
        chart_colors = ['#1e2d3d']

    return jsonify({'labels': labels, 'data': counts, 'colors': chart_colors})


@dashboard_bp.route('/api/dashboard/event-trend')
@login_required
def event_trend():
    days = 14
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=days)

    results = db.session.query(
        func.date(LogRecord.timestamp).label('day'),
        func.count(LogRecord.id).label('count')
    ).filter(
        LogRecord.timestamp >= start_date
    ).group_by(func.date(LogRecord.timestamp)).order_by('day').all()

    day_map = {str(r.day): r.count for r in results}
    labels = []
    data = []
    current = start_date
    while current <= end_date:
        day_str = current.strftime('%Y-%m-%d')
        labels.append(current.strftime('%b %d'))
        data.append(day_map.get(day_str, 0))
        current += timedelta(days=1)

    return jsonify({'labels': labels, 'data': data})


@dashboard_bp.route('/api/dashboard/quick-stats')
@login_required
def quick_stats():
    today = datetime.utcnow().date()
    failed_today = LogRecord.query.filter(
        LogRecord.event_type == 'login_failure',
        func.date(LogRecord.timestamp) == today
    ).count()
    new_alerts = ThreatAlert.query.filter(ThreatAlert.status == 'new').count()
    active_cases = Case.query.filter(Case.status == 'active').count()

    return jsonify({
        'failed_logins_today': failed_today,
        'new_alerts': new_alerts,
        'active_cases': active_cases
    })
