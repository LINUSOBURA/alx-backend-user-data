#!/usr/bin/env python3
"""
Auth module
"""

import uuid

import bcrypt
from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.orm.exc import NoResultFound

from db import DB
from user import User


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
        """Initialize a new Auth instance"""
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Register a new user"""
        try:
            user = self._db.find_user_by(email=email)
            raise ValueError(f"User {user.email} already exists")
        except (InvalidRequestError, NoResultFound):
            user = self._db.add_user(email, _hash_password(password))
            return user

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

    def get_user_from_session_id(self, session_id: str) -> None:
        """Get user from session id"""
        try:
            user = self._db.find_user_by(session_id=session_id)
            return user
        except Exception:
            return None

    def destroy_session(self, user_id: int) -> None:
        """Destroy session"""
        try:
            user = self._db.find_user_by(id=user_id)
            user.session_id = None
            self._db._session.commit()
            return None
        except Exception:
            return None

    def get_reset_password_token(self, email: str) -> str:
        """Get reset password token"""
        user = self._db.find_user_by(email=email)
        if user is None:
            raise ValueError
        reset_token = _generate_uuid()
        user.reset_token = reset_token
        self._db._session.commit()
        return reset_token

    def update_password(self, reset_token: str, password: str) -> None:
        """Updating a user Password"""
        try:
            user = self._db.find_user_by(reset_token=reset_token)
        except ValueError:
            raise ValueError
        user.hashed_password = _hash_password(password)
        user.reset_token = None
        self._db._session.commit()
        return None
