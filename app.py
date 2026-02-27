import os

from dotenv import load_dotenv
from flask import Flask, render_template, redirect, url_for
from flask_login import current_user

from config import get_config
from extensions import db, login_manager, csrf, limiter


def create_app():
    load_dotenv()
    app = Flask(__name__)
    app.config.from_object(get_config())

    # Ensure storage directory exists
    os.makedirs(app.config["STORAGE_DIR"], exist_ok=True)

    # Init extensions
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)
    # Apply default rate limits from config
    default_limit = app.config.get("RATELIMIT_DEFAULT")
    if default_limit:
        limiter.default_limits = [default_limit]

    login_manager.login_view = "auth.login"

    # Import models to register them with SQLAlchemy
    from models import User, File, Share, AuditLog, Folder  # noqa: F401

    # Register blueprints
    from views_auth import auth_bp
    from views_files import files_bp
    from views_admin import admin_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(files_bp)
    app.register_blueprint(admin_bp)

    @app.route("/")
    def index():
        if current_user.is_authenticated:
            return redirect(url_for("files.dashboard"))
        return render_template("index.html")

    # Error handlers
    @app.errorhandler(403)
    def forbidden(e):
        return render_template("error.html", code=403, title="Forbidden", message="You do not have permission to access this resource."), 403

    @app.errorhandler(404)
    def not_found(e):
        return render_template("error.html", code=404, title="Not Found", message="The requested resource could not be found."), 404

    @app.errorhandler(429)
    def too_many_requests(e):
        return render_template("error.html", code=429, title="Too Many Requests", message="You have hit a rate limit. Please try again later."), 429

    @app.errorhandler(500)
    def internal_error(e):
        return render_template("error.html", code=500, title="Server Error", message="An unexpected error occurred. Please try again."), 500

    return app


if __name__ == "__main__":
    flask_app = create_app()
    with flask_app.app_context():
        db.create_all()
        from schema import ensure_sqlite_schema

        ensure_sqlite_schema()
    flask_app.run()

