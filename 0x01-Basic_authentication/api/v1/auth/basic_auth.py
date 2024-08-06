#!/usr/bin/env python3
"""Basic Auth Module"""

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
