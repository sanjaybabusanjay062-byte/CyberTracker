"""
CYBERTRACE AI — WSGI entry point.
Ensures the database is initialized on first startup (e.g. on Render / Railway).
"""
import os
from app import create_app, db

app = create_app()

# Auto-initialize database on first deployment if it doesn't exist
def init_db_if_needed():
    with app.app_context():
        from app.models import User
        try:
            User.query.first()  # Check if tables exist
        except Exception:
            db.create_all()
            print("✓ Database tables created on first startup.")

            # Seed a default admin if none exists
            from app.utils.hashing import hash_password
            from app.models import Case
            admin = User(
                username='admin',
                email='admin@cybertrace.ai',
                password_hash=hash_password('CyberTrace2024!'),
                role='admin',
                is_active=True
            )
            investigator = User(
                username='investigator',
                email='investigator@cybertrace.ai',
                password_hash=hash_password('Invest2024!'),
                role='investigator',
                is_active=True
            )
            db.session.add_all([admin, investigator])
            db.session.commit()
            print("✓ Default admin and investigator accounts created.")

init_db_if_needed()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)
