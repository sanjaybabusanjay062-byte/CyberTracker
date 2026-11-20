import hashlib
import os
from werkzeug.security import generate_password_hash, check_password_hash


def compute_sha256(file_path):
    """Compute SHA-256 hash of a file."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            sha256.update(chunk)
    return sha256.hexdigest()


def verify_integrity(file_path, stored_hash):
    """Verify file integrity against stored hash.
    Returns (is_intact, current_hash).
    """
    if not os.path.exists(file_path):
        return False, None
    current_hash = compute_sha256(file_path)
    return current_hash.lower() == stored_hash.lower(), current_hash


def hash_password(password):
    """Generate secure password hash."""
    return generate_password_hash(password, method='pbkdf2:sha256')


def check_password(password_hash, password):
    """Verify password against password hash."""
    return check_password_hash(password_hash, password)
