#!/usr/bin/env python3
"""
Auth module"""

import uuid

import bcrypt
from sqlalchemy.orm.exc import NoResultFound

from db import DB


def _hash_password(password: str) -> bytes:
    """Hash Password"""
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    return hashed


def _generate_uuid() -> str:
    """Generate a new UUID"""
    return str(uuid.uuid4())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> object:
        """Register a new user"""
        try:
            self._db.find_user_by(email=email)
            raise ValueError(f"User {email} already exists")
        except NoResultFound:
            return self._db.add_user(email, _hash_password(password))

    def valid_login(self, email: str, password: str) -> bool:
        """Validate user login"""
        try:
            return bcrypt.checkpw(
                password.encode(),
                self._db.find_user_by(email=email).hashed_password)
        except Exception:
            return False

    def create_session(self, email: str) -> str:
        """Create a session"""
        try:
            user = self._db.find_user_by(email=email)
            user.session_id = _generate_uuid()
            self._db._session.commit()
            return user.session_id
        except Exception:
            return None
