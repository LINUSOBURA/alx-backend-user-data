#!/usr/bin/env python3
"""Session Auth Model"""
import uuid

from api.v1.auth.auth import Auth


class SessionAuth(Auth):
    """Session Auth Class"""
    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        if not isinstance(user_id, str) or user_id is None:
            return None
        session_id = str(uuid.uuid4())
        self.user_id_by_session_id[session_id] = user_id
        return session_id
