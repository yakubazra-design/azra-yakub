"""Account passwords and session tokens.

Passwords are hashed with Argon2id and a random salt. The database stores the
hash, never the password. A session cookie carries a random token; the database
stores only an HMAC of that token. Signing in does not prove that a source is
authentic.
"""

import hashlib
import hmac
from secrets import token_urlsafe

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

HASHER = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=1,
    hash_len=32,
    salt_len=16,
    type=Type.ID,
)
DUMMY_HASH = HASHER.hash("not-a-real-password")
MIN_SECRET_LENGTH = 32
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 128


def hash_password(password: str) -> str:
    return HASHER.hash(password)


def burn_password_check(password: str) -> None:
    """Spend an Argon2 verification when no account exists."""
    verify_password(DUMMY_HASH, password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return bool(HASHER.verify(password_hash, password))
    except (VerifyMismatchError, InvalidHashError, VerificationError):
        return False


def normalise_email(value: str) -> str | None:
    email = str(value or "").strip().lower()
    if not email or len(email) > 254 or email.count("@") != 1:
        return None
    local, domain = email.split("@")
    if not local or "." not in domain or any(char.isspace() for char in email):
        return None
    return email


def password_acceptable(value: str) -> bool:
    return isinstance(value, str) and MIN_PASSWORD_LENGTH <= len(value) <= MAX_PASSWORD_LENGTH


def new_secret() -> str:
    return token_urlsafe(32)


def session_mac(secret: str, token: str) -> str:
    return hmac.new(secret.encode("utf-8"), token.encode("utf-8"), hashlib.sha256).hexdigest()
