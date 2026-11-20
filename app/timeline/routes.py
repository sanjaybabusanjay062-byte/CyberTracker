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
