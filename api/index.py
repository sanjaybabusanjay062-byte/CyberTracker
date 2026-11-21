import sys
import os
import shutil

# Add project root to sys.path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

# Handle Vercel serverless environment (writable temp filesystem)
is_vercel = bool(os.environ.get('VERCEL') or os.environ.get('VERCEL_ENV') or os.environ.get('AWS_LAMBDA_FUNCTION_NAME'))

if is_vercel:
    import tempfile
    tmp_dir = tempfile.gettempdir()
    tmp_db = os.path.join(tmp_dir, 'cybertrace.db')
    base_db = os.path.join(BASE_DIR, 'cybertrace.db')
    os.makedirs(os.path.join(tmp_dir, 'uploads'), exist_ok=True)
    os.makedirs(os.path.join(tmp_dir, 'reports'), exist_ok=True)

    # Copy pre-seeded database to writable temp directory if not already present
    if not os.path.exists(tmp_db) and os.path.exists(base_db):
        try:
            shutil.copyfile(base_db, tmp_db)
        except Exception as e:
            print(f"[Vercel Init] Could not copy seed db: {e}")

from app import create_app, db

app = create_app()

# If running on Vercel and DB has not been seeded yet, auto-initialize
if is_vercel:
    with app.app_context():
        try:
            db.create_all()
            from app.models import User
            # Quick check if tables exist and have users
            if User.query.count() == 0:
                base_db = os.path.join(BASE_DIR, 'cybertrace.db')
                if os.path.exists(base_db):
                    shutil.copyfile(base_db, tmp_db)
                else:
                    from init_db import create_sample_files, seed_database
                    csv_path, json_path, txt_path = create_sample_files()
                    seed_database(csv_path, json_path, txt_path)
        except Exception as ex:
            print(f"[Vercel Init] Auto-seeding skipped or failed: {ex}")

# WSGI handler for Vercel
if __name__ == '__main__':
    app.run()
