#!/usr/bin/env python3
"""Basic Flask App for Auth service"""

from flask import Flask, abort, jsonify, redirect, request, url_for

from auth import Auth
from db import DB

app = Flask(__name__)
AUTH = Auth()
db = DB()


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
        session_id = AUTH.create_session(email)
        response = jsonify({"email": user.email, "message": "logged in"})
        response.set_cookie('session_id', session_id)
        return response
    except Exception:
        abort(401)


@app.route('/sessions', methods=['DELETE'], strict_slashes=False)
def logout() -> str:
    """Logout a user"""
    session_id = request.cookies.get('session_id')
    if session_id is None:
        abort(403)

    user = AUTH.get_user_from_session_id(session_id)
    if user:
        AUTH.destroy_session(user.id)
        return redirect(url_for('/'))
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
    user = db.find_user_by(email)
    if user is None:
        abort(403)
    token = Auth.get_reset_password_token(email)
    return jsonify({"email": user.email, "reset_token": token})


@app.route('/reset_password', methods=['PUT'], strict_slashes=False)
def update_password() -> str:
    """Updating a user Password"""
    email = request.form.get('email')
    reset_token = request.form.get('reset_token')
    new_password = request.form.get('new_password')

    try:
        user = AUTH.get_user_by_email(email)
        AUTH.update_password(reset_token, new_password)
        return jsonify({"email": user.email, "message": "Password updated"})

    except Exception:
        abort(403)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
