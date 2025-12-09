"""
SecureAuthX — simple authentication helper (single-file)

Features:
- Password hashing using PBKDF2-HMAC-SHA256 with per-user salt
- Safe password verification using hmac.compare_digest
- Simple HMAC-signed tokens with expiry (no external dependencies)
- Optional JSON-backed user store for persistence
- Example CLI usage when run as __main__

Usage example:
    from secureauthx import SecureAuthX
    auth = SecureAuthX(store_path="users.json")
    auth.add_user("alice", "s3cret")
    token = auth.authenticate_user("alice", "s3cret")
    auth.verify_token(token)
"""

import os
import json
import time
import hmac
import base64
import secrets
import hashlib
from typing import Optional, Dict

# ----------------------------- Utilities ---------------------------------

def _b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

def _b64u_decode(s: str) -> bytes:
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + padding).encode("ascii"))

# -------------------------- Password functions ---------------------------

def hash_password(password: str, salt: Optional[str] = None, iterations: int = 200_000) -> str:
    """
    Hash a password with PBKDF2-HMAC-SHA256. Returns a string of the form:
        salt$iterations$hex_digest
    """
    if salt is None:
        salt = secrets.token_hex(16)
    salt_bytes = salt.encode("utf-8")
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt_bytes, iterations)
    return f"{salt}${iterations}${dk.hex()}"

def verify_password(stored: str, provided_password: str) -> bool:
    """
    Verify a stored password string against a provided password.
    """
    try:
        salt, iter_str, hash_hex = stored.split("$")
        iterations = int(iter_str)
    except Exception:
        return False
    salt_bytes = salt.encode("utf-8")
    new_dk = hashlib.pbkdf2_hmac("sha256", provided_password.encode("utf-8"), salt_bytes, iterations)
    return hmac.compare_digest(new_dk.hex(), hash_hex)

# ----------------------------- Token functions ---------------------------

def _sign_message(secret_key: bytes, message: bytes) -> bytes:
    return hmac.new(secret_key, message, hashlib.sha256).digest()

def generate_token_payload(username: str, expiry_unix: int) -> bytes:
    payload = {"u": username, "e": expiry_unix}
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")

def create_token(secret_key: bytes, username: str, ttl_seconds: int = 3600) -> str:
    """
    Create a URL-safe token containing the username and expiry timestamp, signed with HMAC-SHA256.
    Token format: base64url(payload).base64url(signature)
    """
    expiry = int(time.time()) + int(ttl_seconds)
    payload = generate_token_payload(username, expiry)
    payload_b64 = _b64u_encode(payload)
    sig = _sign_message(secret_key, payload)
    sig_b64 = _b64u_encode(sig)
    return f"{payload_b64}.{sig_b64}"

def verify_token(secret_key: bytes, token: str) -> Optional[Dict]:
    """
    Verify token signature and expiry. Returns payload dict on success, otherwise None.
    """
    try:
        payload_b64, sig_b64 = token.split(".")
        payload = _b64u_decode(payload_b64)
        sig = _b64u_decode(sig_b64)
    except Exception:
        return None
    expected_sig = _sign_message(secret_key, payload)
    if not hmac.compare_digest(expected_sig, sig):
        return None
    try:
        data = json.loads(payload.decode("utf-8"))
        if "e" not in data or "u" not in data:
            return None
        if int(data["e"]) < int(time.time()):
            return None  # expired
        return data
    except Exception:
        return None

# --------------------------- User Store class ----------------------------

class SecureAuthX:
    """
    Simple authentication manager.

    Example:
        auth = SecureAuthX(store_path="users.json")  # optional persistent store
        auth.add_user("bob", "password123")
        token = auth.authenticate_user("bob", "password123")
        auth.verify_token(token)
    """
    def __init__(self, store_path: Optional[str] = None, secret_key: Optional[bytes] = None):
        self.store_path = store_path
        self.users: Dict[str, str] = {}  # username -> password_hash
        self.secret_key = secret_key or secrets.token_bytes(32)
        if store_path:
            self._load_store()

    def _load_store(self):
        if self.store_path and os.path.exists(self.store_path):
            with open(self.store_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            # Expecting {username: password_hash, ...}
            if isinstance(data, dict):
                self.users = data

    def _save_store(self):
        if not self.store_path:
            return
        with open(self.store_path, "w", encoding="utf-8") as f:
            json.dump(self.users, f, indent=2, sort_keys=True)

    def add_user(self, username: str, password: str) -> bool:
        if not username or not password:
            return False
        if username in self.users:
            return False
        pwhash = hash_password(password)
        self.users[username] = pwhash
        self._save_store()
        return True

    def remove_user(self, username: str) -> bool:
        if username in self.users:
            del self.users[username]
            self._save_store()
            return True
        return False

    def authenticate_user(self, username: str, password: str, ttl_seconds: int = 3600) -> Optional[str]:
        """
        Verify credentials and return a signed token if successful.
        """
        stored = self.users.get(username)
        if not stored:
            return None
        if verify_password(stored, password):
            return create_token(self.secret_key, username, ttl_seconds)
        return None

    def verify_token(self, token: str) -> Optional[Dict]:
        return verify_token(self.secret_key, token)

# ------------------------------ CLI Demo ---------------------------------

def _demo():
    print("SecureAuthX demo — simple user store in 'users.json' (created in current working dir)\n")
    auth = SecureAuthX(store_path="users.json")
    print("Adding user 'alice' with password 'wonderland'...")
    added = auth.add_user("alice", "wonderland")
    print("Added:", added)
    print("Authenticating 'alice' with correct password...")
    token = auth.authenticate_user("alice", "wonderland", ttl_seconds=20)
    print("Token:", token)
    print("Verifying token immediately...")
    print("Payload:", auth.verify_token(token))
    print("Sleeping 3 seconds then verifying again...")
    time.sleep(3)
    print("Payload:", auth.verify_token(token))
    print("Waiting for token to expire (sleep 22s) ...")
    time.sleep(22)
    print("Payload after expiry (should be None):", auth.verify_token(token))
    print("\nUser store saved to users.json (if using store_path). Remove that file to reset demo.")

if __name__ == "__main__":
    _demo()
