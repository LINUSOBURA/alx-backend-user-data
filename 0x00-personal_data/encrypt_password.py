#!/usr/bin/env python3
"""Encrypt Password"""

import bcrypt


def hash_password(password: str) -> bytes:
    """Hashes a password using the bcrypt algorithm."""
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    return hashed


def is_valid(hashed_password: bytes, password: str) -> bool:
    """Check if a given password matches a hashed password."""
    if bcrypt.checkpw(password.encode(), hashed_password):
        return True
    else:
        return False
