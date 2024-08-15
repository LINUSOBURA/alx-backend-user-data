#!/usr/bin/env python3
"""Basic Flask App"""

from flask import Flask, abort, jsonify, redirect, request

from auth import Auth

app = Flask(__name__)
AUTH = Auth()


@app.route('/', methods=['GET'], strict_slashes=False)
def index() -> str:
    """Default route"""
    return jsonify({"message": "Bienvenue"})


@app.route('/users', methods=['POST'], strict_slashes=False)
def users() -> str:
    """Register a new user"""
    email = request.form.get('email')
    password = request.form.get('password')

    try:
        new_user = AUTH.register_user(email, password)
        return jsonify({"email": new_user.email, "message": "user created"})
    except Exception:
        return jsonify({"message": "email already registered"})


@app.route('/sessions', methods=['POST'], strict_slashes=False)
def login() -> str:
    """Login a user using provided credentials"""
    email = request.form.get('email')
    password = request.form.get('password')

    try:
        user = AUTH.valid_login(email, password)
        AUTH.create_session(email)
        return jsonify({"email": user.email, "message": "logged in"})
    except Exception:
        abort(401)


@app.route('/sessions', methods=['DELETE'], strict_slashes=False)
def logout() -> None:
    """Logout a user"""
    session_id = request.cookies.get('session_id')
    if session_id is None:
        abort(403)

    user = AUTH.get_user_from_session_id(session_id)
    if user is None:
        abort(403)

    try:
        AUTH.destroy_session(user.id)
        redirect('/')
    except Exception:
        abort(403)


@app.route('/profile', methods=['GET'], strict_slashes=False)
def profile() -> str:
    """Get user profile"""
    session_id = request.cookies.get('session_id')
    if session_id is None:
        abort(403)
    try:
        user = Auth.get_user_from_session_id(session_id)
        return jsonify({"email": user.email})
    except Exception:
        abort(403)


@app.route('/reset_password', methods=['POST'], strict_slashes=False)
def get_reset_password_token() -> str:
    """Get reset password token"""
    email = request.form.get('email')
    user = AUTH._db.get_user_by_email(email)
    if user is None:
        abort(403)
    token = Auth.get_reset_password_token(email)
    return jsonify({"email": user.email, "reset_token": token})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
