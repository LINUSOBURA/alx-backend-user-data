#!/usr/bin/env python3
"""
Auth module"""

import bcrypt
from sqlalchemy.orm.exc import NoResultFound

from db import DB


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def _hash_password(self, password: str) -> bytes:
        """Hash Password"""
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        return hashed

    def register_user(self, email: str, password: str) -> object:
        """Register a new user"""
        try:
            self._db.find_user_by(email=email)
            raise ValueError(f"User {email} already exists")
        except NoResultFound:
            return self._db.add_user(email, self._hash_password(password))
