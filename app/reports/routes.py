import os
from flask import render_template, jsonify, request, send_file, current_app
from flask_login import login_required, current_user
from datetime import datetime
from app.reports import reports_bp
from app.models import Case, AuditLog
from app.utils.pdf_generator import generate_investigation_report
from app import db


@reports_bp.route('/reports')
@login_required
def index():
    cases = Case.query.filter(Case.status != 'archived').all()
    return render_template('reports/index.html', title='Forensic Reports', cases=cases)


@reports_bp.route('/api/reports/generate', methods=['POST'])
@login_required
def generate():
    data = request.get_json() or {}
    case_id = data.get('case_id')
    report_type = data.get('report_type', 'full')

    if not case_id:
        return jsonify({'error': 'Case ID is required'}), 400

    case = Case.query.get_or_404(int(case_id))
    reports_folder = current_app.config.get('REPORTS_FOLDER', 'reports')
    os.makedirs(reports_folder, exist_ok=True)

    timestamp_str = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    filename = f'cybertrace_report_{case.case_id}_{timestamp_str}.pdf'
    output_path = os.path.join(reports_folder, filename)

    try:
        generate_investigation_report(case_id=int(case_id), output_path=output_path)
        file_size = os.path.getsize(output_path)

        audit = AuditLog(
            user_id=current_user.id,
            action='REPORT_GENERATED',
            resource_type='case',
            resource_id=case.case_id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', '')[:255],
            details=f'Generated {report_type} report: {filename}'
        )
        db.session.add(audit)
        db.session.commit()

        return jsonify({
            'success': True,
            'filename': filename,
            'case_id': case.case_id,
            'case_title': case.title,
            'file_size': file_size,
            'generated_at': datetime.utcnow().isoformat(),
            'download_url': f'/api/reports/download/{filename}'
        })
    except Exception as e:
        return jsonify({'error': f'Report generation failed: {str(e)}'}), 500


@reports_bp.route('/api/reports/download/<filename>')
@login_required
def download(filename):
    # Security: prevent path traversal
    safe_filename = os.path.basename(filename)
    if not safe_filename.endswith('.pdf'):
        return jsonify({'error': 'Invalid file type'}), 400

    reports_folder = current_app.config.get('REPORTS_FOLDER', 'reports')
    file_path = os.path.join(reports_folder, safe_filename)

    if not os.path.exists(file_path):
        return jsonify({'error': 'Report file not found'}), 404

    audit = AuditLog(
        user_id=current_user.id,
        action='REPORT_DOWNLOADED',
        resource_type='report',
        resource_id=safe_filename,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent', '')[:255]
    )
    db.session.add(audit)
    db.session.commit()

    return send_file(file_path, as_attachment=True, download_name=safe_filename, mimetype='application/pdf')


@reports_bp.route('/api/reports/list')
@login_required
def list_reports():
    reports_folder = current_app.config.get('REPORTS_FOLDER', 'reports')
    if not os.path.exists(reports_folder):
        return jsonify({'reports': []})

    reports = []
    for fname in os.listdir(reports_folder):
        if fname.endswith('.pdf'):
            fpath = os.path.join(reports_folder, fname)
            stat = os.stat(fpath)
            reports.append({
                'filename': fname,
                'file_size': stat.st_size,
                'created_at': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                'download_url': f'/api/reports/download/{fname}'
            })

    reports.sort(key=lambda x: x['created_at'], reverse=True)
    return jsonify({'reports': reports})


@reports_bp.route('/api/reports/delete/<filename>', methods=['DELETE'])
@login_required
def delete_report(filename):
    safe_filename = os.path.basename(filename)
    reports_folder = current_app.config.get('REPORTS_FOLDER', 'reports')
    file_path = os.path.join(reports_folder, safe_filename)
    if os.path.exists(file_path):
        os.remove(file_path)
        return jsonify({'success': True})
    return jsonify({'error': 'File not found'}), 404
