from datetime import datetime
import uuid

from flask_login import UserMixin
from sqlalchemy import func

from extensions import db, login_manager


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    files = db.relationship("File", backref="owner", lazy=True)
    audit_logs = db.relationship("AuditLog", backref="user", lazy=True)

    def get_id(self):
        return str(self.id)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


class Folder(db.Model):
    __tablename__ = "folders"

    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    is_deleted = db.Column(db.Boolean, default=False, nullable=False)

    files = db.relationship("File", backref="folder", lazy=True)


class File(db.Model):
    __tablename__ = "files"

    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    folder_id = db.Column(db.Integer, db.ForeignKey("folders.id"), nullable=True)

    original_filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(255), nullable=False, unique=True)
    mime_type = db.Column(db.String(128), nullable=True)
    size_bytes = db.Column(db.Integer, nullable=False)

    sha256_hash = db.Column(db.String(64), nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    # Enhanced UX fields
    is_deleted = db.Column(db.Boolean, default=False, nullable=False)
    is_starred = db.Column(db.Boolean, default=False, nullable=False)
    last_accessed_at = db.Column(db.DateTime, nullable=True)

    shares = db.relationship("Share", backref="file", lazy=True, cascade="all, delete-orphan")
    versions = db.relationship("FileVersion", backref="file", lazy=True, cascade="all, delete-orphan", order_by="FileVersion.created_at.desc()")
    comments = db.relationship("Comment", backref="file", lazy=True, cascade="all, delete-orphan", order_by="Comment.created_at.desc()")


class Share(db.Model):
    __tablename__ = "shares"

    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey("files.id"), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    # Optional direct user share
    target_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)

    # Token-based public share
    token = db.Column(db.String(64), unique=True, index=True, nullable=False)

    expires_at = db.Column(db.DateTime, nullable=True)
    max_downloads = db.Column(db.Integer, nullable=True)
    download_count = db.Column(db.Integer, default=0, nullable=False)

    is_revoked = db.Column(db.Boolean, default=False, nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class FileVersion(db.Model):
    __tablename__ = "file_versions"

    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey("files.id"), nullable=False)
    stored_filename = db.Column(db.String(255), nullable=False)
    mime_type = db.Column(db.String(128), nullable=True)
    size_bytes = db.Column(db.Integer, nullable=False)
    sha256_hash = db.Column(db.String(64), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    created_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)


class Comment(db.Model):
    __tablename__ = "comments"

    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey("files.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    ip_address = db.Column(db.String(64), nullable=True)
    event_type = db.Column(db.String(64), nullable=False)
    description = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, server_default=func.now(), nullable=False)


def generate_share_token() -> str:
    return uuid.uuid4().hex + uuid.uuid4().hex

