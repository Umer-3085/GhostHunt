"""
GhostHunt — Phase 6: Flask Application Factory & Central Configuration
Authoritative Flask application factory specified in DEVELOPMENT_ROADMAP.md (Version 1.4.3).

Architectural & Security Guarantees:
1. Localhost-only deployment binding (127.0.0.1).
2. Explicit single-process configuration: debug=False, use_reloader=False.
3. Centralized configuration with secure session cookies (HttpOnly, SameSite=Lax).
4. Request size limits (MAX_CONTENT_LENGTH = 1 MB) to prevent denial of service.
5. Consistent JSON error responses for API endpoints and styled HTML for page routes.
6. Auto-escaping enabled by default in Jinja2 to prevent XSS.
7. Explicit scheduler lifecycle control (never started on import).
"""

import logging
import os
import secrets
from typing import Any, Dict, Optional

from flask import Flask, abort, jsonify, render_template, request, session

import config

logger = logging.getLogger("ghosthunt.dashboard")


def create_app(config_override: Optional[Dict[str, Any]] = None) -> Flask:
    """
    Creates and configures the GhostHunt Flask application instance.
    """
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )

    # 1. Centralized Application Configuration
    app.config["SECRET_KEY"] = config.SECRET_KEY
    app.config["DB_PATH"] = config.DB_PATH
    app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024  # 1 MB maximum payload
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = False  # Localhost HTTP deployment
    app.config["JSON_SORT_KEYS"] = False

    # Apply configuration overrides (e.g. test database paths)
    if config_override:
        app.config.update(config_override)

    # 2. Request Size & CSRF Protection Middleware
    @app.before_request
    def check_request_size() -> None:
        """Enforces MAX_CONTENT_LENGTH before processing request body."""
        cl = request.content_length
        max_len = app.config.get("MAX_CONTENT_LENGTH")
        if cl is not None and max_len is not None and cl > max_len:
            abort(413, description="Request payload exceeds 1 MB limit")

    @app.before_request
    def ensure_csrf_token() -> None:
        """Ensures a session CSRF token exists for browser interactions."""
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_hex(32)

    # 3. Structured Error Handlers (No Stack Trace Leakage)
    @app.errorhandler(400)
    def bad_request(error: Any):
        if request.path.startswith("/api/"):
            return jsonify({
                "success": False,
                "error": "Bad Request",
                "message": getattr(error, "description", "Malformed request"),
            }), 400
        return render_template("base.html", error_title="400 - Bad Request", error_message=str(error)), 400

    @app.errorhandler(404)
    def not_found(error: Any):
        if request.path.startswith("/api/"):
            return jsonify({
                "success": False,
                "error": "Not Found",
                "message": getattr(error, "description", "Resource not found"),
            }), 404
        return render_template("base.html", error_title="404 - Not Found", error_message=str(error)), 404

    @app.errorhandler(405)
    def method_not_allowed(error: Any):
        if request.path.startswith("/api/"):
            return jsonify({
                "success": False,
                "error": "Method Not Allowed",
                "message": getattr(error, "description", "HTTP method not allowed"),
            }), 405
        return render_template("base.html", error_title="405 - Method Not Allowed", error_message=str(error)), 405

    @app.errorhandler(409)
    def conflict(error: Any):
        msg = getattr(error, "description", "Another protected operation is in progress")
        if request.path.startswith("/api/"):
            return jsonify({
                "success": False,
                "status": "busy",
                "error": "Conflict",
                "message": msg,
            }), 409
        return render_template("base.html", error_title="409 - Conflict", error_message=msg), 409

    @app.errorhandler(413)
    def request_entity_too_large(error: Any):
        if request.path.startswith("/api/"):
            return jsonify({
                "success": False,
                "error": "Payload Too Large",
                "message": "Request payload exceeds 1 MB limit",
            }), 413
        return render_template("base.html", error_title="413 - Payload Too Large", error_message="Request payload exceeds limit"), 413

    @app.errorhandler(500)
    def internal_server_error(error: Any):
        logger.error("Unhandled internal server error: %s", error, exc_info=True)
        if request.path.startswith("/api/"):
            return jsonify({
                "success": False,
                "error": "Internal Server Error",
                "message": "An unexpected error occurred. Consult server logs.",
            }), 500
        return render_template("base.html", error_title="500 - Internal Server Error", error_message="An unexpected server error occurred."), 500

    # 4. Context Processors for Templates
    @app.context_processor
    def inject_global_template_vars() -> Dict[str, Any]:
        return {
            "app_name": config.APP_NAME,
            "app_version": config.APP_VERSION,
            "csrf_token": session.get("csrf_token", ""),
        }

    # 5. Register Routes Blueprint
    from dashboard.routes import dashboard_bp
    app.register_blueprint(dashboard_bp)

    return app
