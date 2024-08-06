#!/usr/bin/env python3
"""Basic Auth Module"""

import base64
from typing import TypeVar

from models.user import User

from api.v1.auth.auth import Auth


class BasicAuth(Auth):
    """BasicAuth Class"""

    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """Returns the Base64 part of the Authorization"""
        if type(authorization_header
                ) is not str or authorization_header is None:
            return None
        if not authorization_header.startswith('Basic '):
            return None
        else:
            return authorization_header[6:]

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """Returns the decoded value of base64_authorization_header"""
        if not isinstance(base64_authorization_header,
                          str) or base64_authorization_header is None:
            return None

        try:
            padded_base64 = base64_authorization_header + '=='
            decoded = base64.b64decode(padded_base64)
            return decoded.decode('utf-8')
        except (TypeError, base64.binascii.Error, UnicodeDecodeError):
            return None

    def extract_user_credentials(
            self, decoded_base64_authorization_header: str) -> (str, str):
        """Returns the user email and password"""
        if not isinstance(decoded_base64_authorization_header,
                          str) or decoded_base64_authorization_header is None:
            return None, None
        if ':' not in decoded_base64_authorization_header:
            return None, None
        else:
            email, password = decoded_base64_authorization_header.split(':', 1)
            return email, password

    def user_object_from_credentials(self, user_email: str,
                                     user_pwd: str) -> TypeVar('User'):
        """Returns the User instance based on his email and password"""
        if not isinstance(user_email, str) or not isinstance(user_pwd, str):
            return None
        if user_email is None or user_pwd is None:
            return None
        try:
            users = User.search({'email': user_email})
            if not users:
                return None
            user = users[0]
            if not user.is_valid_password(user_pwd):
                return None
            return user

        except Exception:
            return None
