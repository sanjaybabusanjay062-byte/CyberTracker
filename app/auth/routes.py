from flask import render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash
from datetime import datetime
from app.auth import auth_bp
from app.models import User, AuditLog
from app import db


def log_audit(action, resource_type=None, resource_id=None, details=None):
    entry = AuditLog(
        user_id=current_user.id if current_user.is_authenticated else None,
        action=action,
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id else None,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent', '')[:255],
        details=details
    )
    db.session.add(entry)
    db.session.commit()


@auth_bp.route('/login', methods=['GET', 'POST'])
@auth_bp.route('/', methods=['GET'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))

    if request.method == 'POST':
        ident = (request.form.get('username') or request.form.get('email', '')).strip()
        password = request.form.get('password', '')
        remember = request.form.get('remember', False)

        if not ident or not password:
            flash('Identifier (username or email) and password are required.', 'error')
            return render_template('auth/login.html')

        user = User.query.filter(
            (User.email == ident) | (User.username == ident)
        ).first()

        if user and user.is_active and check_password_hash(user.password_hash, password):
            login_user(user, remember=bool(remember))
            user.last_login = datetime.utcnow()
            db.session.commit()

            # Audit log
            entry = AuditLog(
                user_id=user.id,
                action='LOGIN_SUCCESS',
                resource_type='auth',
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent', '')[:255],
                details=f'User {user.username} logged in successfully'
            )
            db.session.add(entry)
            db.session.commit()

            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard.index'))
        else:
            # Failed login audit
            entry = AuditLog(
                user_id=None,
                action='LOGIN_FAILED',
                resource_type='auth',
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent', '')[:255],
                details=f'Failed login attempt for identifier: {ident}'
            )
            db.session.add(entry)
            db.session.commit()
            flash('Invalid credentials. Please verify your investigator username and passkey.', 'error')

    return render_template('auth/login.html')


@auth_bp.route('/logout')
@login_required
def logout():
    entry = AuditLog(
        user_id=current_user.id,
        action='LOGOUT',
        resource_type='auth',
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent', '')[:255],
        details=f'User {current_user.email} logged out'
    )
    db.session.add(entry)
    db.session.commit()
    logout_user()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('auth.login'))


@auth_bp.route('/profile')
@login_required
def profile():
    return render_template('auth/profile.html', user=current_user)
