import uuid
from flask import render_template, jsonify, request
from flask_login import login_required, current_user
from app.ai_assistant import ai_bp
from app.models import ChatMessage, Case, Evidence
from app.utils.ai_engine import QueryEngine
from app import db


query_engine = QueryEngine()


@ai_bp.route('/ai-assistant')
@login_required
def index():
    cases = Case.query.filter(Case.status != 'archived').all()
    return render_template('ai_assistant/index.html', title='AI Investigation Assistant', cases=cases)


@ai_bp.route('/api/chat/query', methods=['POST'])
@login_required
def query():
    data = request.get_json() or {}
    question = data.get('question', '').strip()
    case_id = data.get('case_id')
    session_id = data.get('session_id', str(uuid.uuid4()))

    if not question:
        return jsonify({'error': 'Question is required'}), 400

    # Save user message
    user_msg = ChatMessage(
        session_id=session_id,
        case_id=int(case_id) if case_id else None,
        user_id=current_user.id,
        role='user',
        content=question
    )
    db.session.add(user_msg)

    # Query the AI engine
    result = query_engine.query(question, case_id=int(case_id) if case_id else None)

    # Save assistant response
    assistant_msg = ChatMessage(
        session_id=session_id,
        case_id=int(case_id) if case_id else None,
        user_id=current_user.id,
        role='assistant',
        content=result['answer']
    )
    assistant_msg.set_related_log_ids([r.get('id') for r in result.get('supporting_records', []) if r.get('id')])
    db.session.add(assistant_msg)
    db.session.commit()

    return jsonify({
        'answer': result['answer'],
        'supporting_records': result.get('supporting_records', []),
        'confidence': result.get('confidence', 'medium'),
        'disclaimer': result.get('disclaimer', 'Analysis based on available evidence only.'),
        'session_id': session_id
    })


@ai_bp.route('/api/chat/history/<session_id>')
@login_required
def history(session_id):
    messages = ChatMessage.query.filter_by(session_id=session_id).order_by(ChatMessage.timestamp.asc()).all()
    return jsonify({'messages': [m.to_dict() for m in messages]})


@ai_bp.route('/api/chat/history/<session_id>', methods=['DELETE'])
@login_required
def clear_history(session_id):
    ChatMessage.query.filter_by(session_id=session_id).delete()
    db.session.commit()
    return jsonify({'success': True, 'message': 'Conversation cleared'})
