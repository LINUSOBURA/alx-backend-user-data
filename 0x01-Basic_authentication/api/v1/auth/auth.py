#!/usr/bin/env python3
"""Auth Module"""
from typing import List, TypeVar

from flask import request


class Auth:
    """Auth Class"""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Check if authentication is required for the given path."""
        return False

    def authorization_header(self, request=None) -> str:
        """Returns the authorization header for the given request."""
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """ Returns the current user associated with the given request."""
        return None
