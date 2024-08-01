#!/usr/bin/env python3
"""Encrypt Password"""

import bcrypt


def hash_password(password: str) -> bytes:
    """Hashes a password using the bcrypt algorithm."""
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    return hashed
