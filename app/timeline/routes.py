from flask import render_template, jsonify, request
from flask_login import login_required
from datetime import datetime
from sqlalchemy import or_
from app.timeline import timeline_bp
from app.models import LogRecord, Case
from app import db


@timeline_bp.route('/timeline')
@login_required
def index():
    cases = Case.query.filter(Case.status != 'archived').all()
    return render_template('timeline/index.html', title='Incident Timeline', cases=cases)


@timeline_bp.route('/api/timeline/events')
@login_required
def events():
    case_id = request.args.get('case_id')
    severity = request.args.get('severity')
    event_type = request.args.get('event_type')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    limit = int(request.args.get('limit', 200))

    q = LogRecord.query
    if case_id:
        q = q.filter(LogRecord.case_id == int(case_id))
    if severity:
        q = q.filter(LogRecord.severity == severity)
    if event_type:
        q = q.filter(LogRecord.event_type == event_type)
    if start_date:
        try:
            q = q.filter(LogRecord.timestamp >= datetime.fromisoformat(start_date))
        except Exception:
            pass
    if end_date:
        try:
            q = q.filter(LogRecord.timestamp <= datetime.fromisoformat(end_date))
        except Exception:
            pass

    records = q.order_by(LogRecord.timestamp.asc()).limit(limit).all()

    return jsonify({
        'events': [r.to_dict() for r in records],
        'total': len(records)
    })


@timeline_bp.route('/api/timeline/export')
@login_required
def export_timeline():
    import csv
    import io
    from flask import Response
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

    records = q.order_by(LogRecord.timestamp.asc()).limit(5000).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Chronological Index', 'Timestamp (UTC)', 'Source IP', 'Target Host/IP', 'User Account', 'Event Type', 'Severity', 'Forensic Description', 'Suspicious Flag'])
    
    for idx, r in enumerate(records, 1):
        writer.writerow([
            idx,
            r.timestamp.isoformat() if r.timestamp else '',
            r.source_ip or 'Local',
            r.destination_ip or '',
            r.username or '',
            r.event_type,
            r.severity.upper() if r.severity else 'INFO',
            r.event_description,
            'YES' if r.is_suspicious else 'NO'
        ])

    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=cybertrace_incident_timeline.csv'}
    )
