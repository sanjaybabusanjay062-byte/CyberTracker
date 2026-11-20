from flask import render_template, jsonify, request
from flask_login import login_required, current_user
from datetime import datetime
from app.cases import cases_bp
from app.models import Case, CaseNote, Evidence, ThreatAlert, AuditLog, User
from app import db


def generate_case_id():
    year = datetime.utcnow().year
    count = Case.query.count()
    return f'CT-{year}-{count + 1:03d}'


@cases_bp.route('/cases')
@login_required
def index():
    return render_template('cases/index.html', title='Case Management')


@cases_bp.route('/api/cases', methods=['POST'])
@login_required
def create_case():
    data = request.get_json() or {}
    title = data.get('title', '').strip()
    if not title:
        return jsonify({'error': 'Case title is required'}), 400

    case = Case(
        case_id=generate_case_id(),
        title=title,
        description=data.get('description', ''),
        status='open',
        priority=data.get('priority', 'medium'),
        investigator_id=current_user.id
    )
    db.session.add(case)

    audit = AuditLog(
        user_id=current_user.id,
        action='CASE_CREATED',
        resource_type='case',
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent', '')[:255],
        details=f'Created case: {title}'
    )
    db.session.add(audit)
    db.session.commit()
    return jsonify({'success': True, 'case': case.to_dict()}), 201


@cases_bp.route('/api/cases/list')
@login_required
def list_cases():
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 20))
    status = request.args.get('status')
    priority = request.args.get('priority')

    q = Case.query
    if status:
        q = q.filter(Case.status == status)
    if priority:
        q = q.filter(Case.priority == priority)

    total = q.count()
    cases = q.order_by(Case.created_at.desc()).offset((page - 1) * per_page).limit(per_page).all()

    return jsonify({
        'cases': [c.to_dict() for c in cases],
        'total': total,
        'page': page,
        'pages': (total + per_page - 1) // per_page
    })


@cases_bp.route('/api/cases/<int:case_id>')
@login_required
def get_case(case_id):
    case = Case.query.get_or_404(case_id)
    data = case.to_dict()
    data['evidence'] = [e.to_dict() for e in case.evidence_items if e.status != 'deleted']
    data['recent_alerts'] = [a.to_dict() for a in case.threat_alerts[:5]]
    return jsonify(data)


@cases_bp.route('/api/cases/<int:case_id>', methods=['PATCH'])
@login_required
def update_case(case_id):
    case = Case.query.get_or_404(case_id)
    data = request.get_json() or {}

    if 'title' in data:
        case.title = data['title']
    if 'description' in data:
        case.description = data['description']
    if 'status' in data:
        case.status = data['status']
        if data['status'] == 'closed':
            case.closed_at = datetime.utcnow()
    if 'priority' in data:
        case.priority = data['priority']
    case.updated_at = datetime.utcnow()

    audit = AuditLog(
        user_id=current_user.id,
        action='CASE_UPDATED',
        resource_type='case',
        resource_id=case.case_id,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent', '')[:255],
        details=f'Updated fields: {list(data.keys())}'
    )
    db.session.add(audit)
    db.session.commit()
    return jsonify({'success': True, 'case': case.to_dict()})


@cases_bp.route('/api/cases/<int:case_id>', methods=['DELETE'])
@login_required
def delete_case(case_id):
    case = Case.query.get_or_404(case_id)
    case.status = 'archived'
    case.updated_at = datetime.utcnow()
    audit = AuditLog(
        user_id=current_user.id,
        action='CASE_ARCHIVED',
        resource_type='case',
        resource_id=case.case_id,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent', '')[:255]
    )
    db.session.add(audit)
    db.session.commit()
    return jsonify({'success': True, 'message': 'Case archived'})


@cases_bp.route('/api/cases/<int:case_id>/notes', methods=['POST'])
@login_required
def add_note(case_id):
    case = Case.query.get_or_404(case_id)
    data = request.get_json() or {}
    content = data.get('content', '').strip()
    if not content:
        return jsonify({'error': 'Note content is required'}), 400

    note = CaseNote(
        case_id=case_id,
        author_id=current_user.id,
        content=content,
        note_type=data.get('note_type', 'general')
    )
    db.session.add(note)
    db.session.commit()
    return jsonify({'success': True, 'note': note.to_dict()}), 201


@cases_bp.route('/api/cases/<int:case_id>/notes')
@login_required
def get_notes(case_id):
    notes = CaseNote.query.filter_by(case_id=case_id).order_by(CaseNote.timestamp.desc()).all()
    return jsonify({'notes': [n.to_dict() for n in notes]})
