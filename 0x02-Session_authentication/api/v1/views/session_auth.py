#!/usr/bin/env python3
"""Session_auth module"""
from flask import Blueprint, abort, current_app, jsonify, request

from api.v1.auth import auth
from api.v1.views import app_views
from models.user import User


@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def login():
    """ POST /api/v1/auth_session/login
    Handles user login and session creation.
    """
    email = request.form.get('email')
    password = request.form.get('password')

    # Check for missing parameters
    if not email:
        return jsonify({"error": "email missing"}), 400
    if not password:
        return jsonify({"error": "password missing"}), 400

    # Retrieve the User instance
    users = User.search({'email': email})
    if not users:
        return jsonify({"error": "no user found for this email"}), 404

    user = users[0]  # Assuming the first user in the list is the correct one
    if not user.is_valid_password(password):
        return jsonify({"error": "wrong password"}), 401

    # Create a Session ID
    session_id = auth.create_session(user.id)
    if session_id is None:
        return jsonify({"error": "could not create session"}), 500

    # Create response and set cookie
    response = jsonify(user.to_json())
    session_name = current_app.config.get('SESSION_NAME', '_my_session_id')
    response.set_cookie(session_name, session_id)

    return response


@app_views.route('/auth_session/logout',
                 methods=['DELETE'],
                 strict_slashes=False)
def logout():
    """ DELETE /api/v1/auth_session/logout
    Handles user logout and session destruction.
    """
    if not auth.destroy_session(request):
        abort(404)
    return jsonify({}), 200
