import os
from datetime import datetime, timedelta

from flask import (
    Blueprint,
    render_template,
    redirect,
    url_for,
    flash,
    request,
    send_file,
    abort,
)
from flask_login import login_required, current_user
from flask_wtf import FlaskForm
from wtforms import FileField, StringField, IntegerField, DateTimeLocalField, SubmitField, SelectField
from wtforms.validators import DataRequired, Optional, NumberRange, Length
from werkzeug.utils import secure_filename
from io import BytesIO

from extensions import db, limiter
from models import File, Share, User, Folder, FileVersion, Comment, generate_share_token
from security import encrypt_file_bytes, decrypt_file_bytes
from audit import log_event
from flask import current_app


files_bp = Blueprint("files", __name__, url_prefix="/files")


class UploadForm(FlaskForm):
    file = FileField("File", validators=[DataRequired()])
    folder_id = SelectField("Folder", coerce=int, validators=[Optional()])
    submit = SubmitField("Upload")


class ShareForm(FlaskForm):
    target_email = StringField("Share with user (optional)", validators=[Optional()])
    expires_at = DateTimeLocalField(
        "Expires At (optional)",
        format="%Y-%m-%dT%H:%M",
        validators=[Optional()],
    )
    max_downloads = IntegerField(
        "Max Downloads (optional)",
        validators=[Optional(), NumberRange(min=1)],
    )
    submit = SubmitField("Create Share Link")


@files_bp.route("/dashboard")
@login_required
def dashboard():
    view = request.args.get("view", "all")
    folder_id = request.args.get("folder", type=int)
    q = request.args.get("q", "").strip()

    base_query = File.query.filter_by(owner_id=current_user.id)

    # Overall stats from all non-deleted files
    all_files = base_query.filter_by(is_deleted=False).all()
    total_files = len(all_files)
    total_storage_bytes = sum(f.size_bytes for f in all_files)
    total_storage_mb = total_storage_bytes / (1024 * 1024) if total_storage_bytes else 0
    starred_count = sum(1 for f in all_files if f.is_starred)

    if folder_id:
        base_query = base_query.filter_by(folder_id=folder_id)

    # Main list: overview (non-deleted) or trash
    if view == "deleted":
        files = base_query.filter_by(is_deleted=True)
    else:
        files = base_query.filter_by(is_deleted=False)

    if q:
        files = files.filter(File.original_filename.ilike(f"%{q}%"))

    files = files.order_by(File.created_at.desc()).all()

    shares = (
        Share.query.filter_by(owner_id=current_user.id)
        .order_by(Share.created_at.desc())
        .all()
    )
    # Folders for sidebar/folder picker
    folders = (
        Folder.query.filter_by(owner_id=current_user.id, is_deleted=False)
        .order_by(Folder.created_at.asc())
        .all()
    )

    # Recent activity for activity monitor
    from models import AuditLog

    recent_activity = (
        AuditLog.query.filter_by(user_id=current_user.id)
        .order_by(AuditLog.created_at.desc())
        .limit(10)
        .all()
    )

    # Starred & recent sections (always from non-deleted files)
    starred_files = (
        File.query.filter_by(owner_id=current_user.id, is_deleted=False, is_starred=True)
        .order_by(File.created_at.desc())
        .limit(6)
        .all()
    )
    recent_files = (
        File.query.filter_by(owner_id=current_user.id, is_deleted=False)
        .order_by(File.last_accessed_at.desc().nullslast(), File.created_at.desc())
        .limit(6)
        .all()
    )

    return render_template(
        "dashboard.html",
        files=files,
        shares=shares,
        folders=folders,
        current_view=view,
        current_folder_id=folder_id,
        recent_activity=recent_activity,
        starred_files=starred_files,
        recent_files=recent_files,
        total_files=total_files,
        total_storage_mb=total_storage_mb,
        starred_count=starred_count,
    )


@files_bp.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    form = UploadForm()
    folders = (
        Folder.query.filter_by(owner_id=current_user.id, is_deleted=False)
        .order_by(Folder.created_at.asc())
        .all()
    )
    # Populate folder choices (0 means "no folder")
    form.folder_id.choices = [(0, "No folder")] + [(f.id, f.name) for f in folders]
    if form.validate_on_submit():
        uploaded = form.file.data
        original_name = secure_filename(uploaded.filename or "")

        if not original_name:
            flash("Invalid filename.", "danger")
            return redirect(url_for("files.upload"))

        data = uploaded.read()
        if not data:
            flash("File is empty.", "warning")
            return redirect(url_for("files.upload"))

        max_size = 20 * 1024 * 1024  # 20 MB
        if len(data) > max_size:
            flash("File too large (max 20MB).", "danger")
            return redirect(url_for("files.upload"))

        encrypted_bytes, digest = encrypt_file_bytes(data, associated_data=original_name.encode())

        stored_name = f"{current_user.id}_{int(datetime.utcnow().timestamp())}_{original_name}"
        storage_path = os.path.join(current_app.config["STORAGE_DIR"], stored_name)

        with open(storage_path, "wb") as f:
            f.write(encrypted_bytes)

        folder_id = form.folder_id.data or None

        f_model = File(
            owner_id=current_user.id,
            original_filename=original_name,
            stored_filename=stored_name,
            mime_type=uploaded.mimetype,
            size_bytes=len(data),
            sha256_hash=digest,
            folder_id=folder_id if folder_id != 0 else None,
        )
        db.session.add(f_model)
        db.session.flush()

        version = FileVersion(
            file_id=f_model.id,
            stored_filename=stored_name,
            mime_type=uploaded.mimetype,
            size_bytes=len(data),
            sha256_hash=digest,
            created_by_id=current_user.id,
        )
        db.session.add(version)
        db.session.commit()
        log_event("file_upload", f"Uploaded file {original_name}", user=current_user, file=f_model)
        flash("File uploaded securely.", "success")
        return redirect(url_for("files.dashboard"))

    return render_template("upload.html", form=form, folders=folders)


def _check_file_access(file: File) -> bool:
    return file.owner_id == current_user.id or current_user.is_admin


@files_bp.route("/download/<int:file_id>")
@login_required
@limiter.limit("20 per hour")
def download(file_id: int):
    f_model = File.query.get_or_404(file_id)
    if not _check_file_access(f_model):
        log_event("unauthorized_download", f"Unauthorized access attempt to file {file_id}", user=current_user, file=f_model)
        abort(403)

    storage_path = os.path.join(current_app.config["STORAGE_DIR"], f_model.stored_filename)
    if not os.path.exists(storage_path):
        flash("File not found on server.", "danger")
        abort(404)

    with open(storage_path, "rb") as f:
        encrypted_bytes = f.read()

    plaintext = decrypt_file_bytes(encrypted_bytes, associated_data=f_model.original_filename.encode())
    f_model.last_accessed_at = datetime.utcnow()
    db.session.commit()
    log_event("file_download", f"Downloaded file {f_model.original_filename}", user=current_user, file=f_model)

    return send_file(
        BytesIO(plaintext),
        as_attachment=True,
        download_name=f_model.original_filename,
        mimetype=f_model.mime_type or "application/octet-stream",
    )


@files_bp.route("/share/<int:file_id>", methods=["GET", "POST"])
@login_required
def share(file_id: int):
    f_model = File.query.get_or_404(file_id)
    if f_model.owner_id != current_user.id:
        abort(403)

    form = ShareForm()
    share_link = None

    if form.validate_on_submit():
        target_user = None
        if form.target_email.data:
            target_user = User.query.filter_by(email=form.target_email.data.lower()).first()
            if not target_user:
                flash("Target user not found.", "warning")
                return redirect(url_for("files.share", file_id=file_id))

        token = generate_share_token()
        share = Share(
            file_id=f_model.id,
            owner_id=current_user.id,
            target_user_id=target_user.id if target_user else None,
            token=token,
            expires_at=form.expires_at.data if form.expires_at.data else None,
            max_downloads=form.max_downloads.data if form.max_downloads.data else None,
        )
        db.session.add(share)
        db.session.commit()

        share_link = url_for("files.access_share", token=token, _external=True)
        log_event("file_share", f"Created share for file {f_model.id}", user=current_user)
        flash("Share link created.", "success")

    return render_template("share.html", file=f_model, form=form, share_link=share_link)


@files_bp.route("/share/access/<token>")
@limiter.limit("30 per hour")
def access_share(token: str):
    share = Share.query.filter_by(token=token).first_or_404()

    if share.is_revoked:
        flash("This share has been revoked.", "warning")
        abort(403)

    if share.expires_at and datetime.utcnow() > share.expires_at:
        flash("This share has expired.", "warning")
        abort(403)

    if share.max_downloads is not None and share.download_count >= share.max_downloads:
        flash("Download limit reached for this share.", "warning")
        abort(403)

    f_model = share.file
    storage_path = os.path.join(current_app.config["STORAGE_DIR"], f_model.stored_filename)
    if not os.path.exists(storage_path):
        flash("File not found on server.", "danger")
        abort(404)

    if share.target_user_id:
        if not current_user.is_authenticated or current_user.id != share.target_user_id:
            flash("You are not authorized to access this shared file.", "danger")
            abort(403)

    with open(storage_path, "rb") as f:
        encrypted_bytes = f.read()

    plaintext = decrypt_file_bytes(encrypted_bytes, associated_data=f_model.original_filename.encode())
    share.download_count += 1
    f_model.last_accessed_at = datetime.utcnow()
    db.session.commit()

    log_event("share_download", f"Downloaded shared file {f_model.id}", user=current_user if current_user.is_authenticated else None, file=f_model)

    return send_file(
        BytesIO(plaintext),
        as_attachment=True,
        download_name=f_model.original_filename,
        mimetype=f_model.mime_type or "application/octet-stream",
    )


@files_bp.route("/share/revoke/<int:share_id>", methods=["POST"])
@login_required
def revoke_share(share_id: int):
    share = Share.query.get_or_404(share_id)
    if share.owner_id != current_user.id and not current_user.is_admin:
        abort(403)

    share.is_revoked = True
    db.session.commit()
    log_event("share_revoke", f"Revoked share {share_id}", user=current_user)
    flash("Share revoked.", "info")
    return redirect(url_for("files.dashboard"))


@files_bp.route("/star/<int:file_id>", methods=["POST"])
@login_required
def toggle_star(file_id: int):
    f_model = File.query.get_or_404(file_id)
    if not _check_file_access(f_model):
        abort(403)
    f_model.is_starred = not f_model.is_starred
    db.session.commit()
    return redirect(url_for("files.dashboard", view=request.args.get("view", "all")))


@files_bp.route("/delete/<int:file_id>", methods=["POST"])
@login_required
def delete_file(file_id: int):
    f_model = File.query.get_or_404(file_id)
    if f_model.owner_id != current_user.id and not current_user.is_admin:
        abort(403)
    f_model.is_deleted = True
    db.session.commit()
    log_event("file_delete", f"Moved file {f_model.id} to trash", user=current_user, file=f_model)
    flash("File moved to Deleted.", "info")
    return redirect(url_for("files.dashboard", view=request.args.get("view", "all")))


@files_bp.route("/restore/<int:file_id>", methods=["POST"])
@login_required
def restore_file(file_id: int):
    f_model = File.query.get_or_404(file_id)
    if f_model.owner_id != current_user.id and not current_user.is_admin:
        abort(403)
    f_model.is_deleted = False
    db.session.commit()
    log_event("file_restore", f"Restored file {f_model.id} from trash", user=current_user, file=f_model)
    flash("File restored.", "success")
    return redirect(url_for("files.dashboard", view=request.args.get("view", "all")))


class FolderForm(FlaskForm):
    name = StringField("Folder name", validators=[DataRequired(), Length(max=255)])
    submit = SubmitField("Create folder")


@files_bp.route("/folders/create", methods=["POST"])
@login_required
def create_folder():
    name = request.form.get("name", "").strip()
    if not name:
        flash("Folder name is required.", "danger")
        return redirect(url_for("files.dashboard"))
    folder = Folder(owner_id=current_user.id, name=name)
    db.session.add(folder)
    db.session.commit()
    flash("Folder created.", "success")
    return redirect(url_for("files.dashboard"))


class CommentForm(FlaskForm):
    content = StringField("Add a comment", validators=[DataRequired(), Length(max=500)])
    submit = SubmitField("Post")


class VersionUploadForm(FlaskForm):
    file = FileField("New version", validators=[DataRequired()])
    submit = SubmitField("Upload new version")


@files_bp.route("/details/<int:file_id>", methods=["GET", "POST"])
@login_required
def details(file_id: int):
    f_model = File.query.get_or_404(file_id)
    if not _check_file_access(f_model):
        abort(403)

    comment_form = CommentForm()
    version_form = VersionUploadForm()

    if comment_form.validate_on_submit() and comment_form.submit.data:
        comment = Comment(file_id=f_model.id, user_id=current_user.id, content=comment_form.content.data.strip())
        db.session.add(comment)
        db.session.commit()
        log_event("comment", f"Commented on file {f_model.id}", user=current_user, file=f_model)
        flash("Comment added.", "success")
        return redirect(url_for("files.details", file_id=file_id))

    versions = f_model.versions

    from models import AuditLog

    activity = (
        AuditLog.query.filter(
            AuditLog.description.ilike(f"%file {f_model.id}%")
        )
        .order_by(AuditLog.created_at.desc())
        .limit(20)
        .all()
    )

    comments = f_model.comments

    return render_template(
        "file_details.html",
        file=f_model,
        versions=versions,
        comments=comments,
        activity=activity,
        comment_form=comment_form,
        version_form=version_form,
    )


@files_bp.route("/details/<int:file_id>/upload_version", methods=["POST"])
@login_required
def upload_version(file_id: int):
    f_model = File.query.get_or_404(file_id)
    if f_model.owner_id != current_user.id:
        abort(403)

    form = VersionUploadForm()
    if not form.validate_on_submit():
        flash("Please choose a file to upload.", "danger")
        return redirect(url_for("files.details", file_id=file_id))

    uploaded = form.file.data
    original_name = secure_filename(uploaded.filename or "")
    data = uploaded.read()
    if not data:
        flash("File is empty.", "warning")
        return redirect(url_for("files.details", file_id=file_id))

    encrypted_bytes, digest = encrypt_file_bytes(data, associated_data=original_name.encode())
    stored_name = f"{current_user.id}_{int(datetime.utcnow().timestamp())}_v{f_model.id}_{original_name}"
    storage_path = os.path.join(current_app.config["STORAGE_DIR"], stored_name)
    with open(storage_path, "wb") as f:
        f.write(encrypted_bytes)

    # Snapshot current version before overwriting
    current_version = FileVersion(
        file_id=f_model.id,
        stored_filename=f_model.stored_filename,
        mime_type=f_model.mime_type,
        size_bytes=f_model.size_bytes,
        sha256_hash=f_model.sha256_hash,
        created_by_id=current_user.id,
    )
    db.session.add(current_version)

    # Update file to new version
    f_model.stored_filename = stored_name
    f_model.mime_type = uploaded.mimetype
    f_model.size_bytes = len(data)
    f_model.sha256_hash = digest
    f_model.last_accessed_at = datetime.utcnow()

    new_version = FileVersion(
        file_id=f_model.id,
        stored_filename=stored_name,
        mime_type=uploaded.mimetype,
        size_bytes=len(data),
        sha256_hash=digest,
        created_by_id=current_user.id,
    )
    db.session.add(new_version)
    db.session.commit()
    log_event("file_new_version", f"Uploaded new version for file {f_model.id}", user=current_user, file=f_model)
    flash("New version uploaded.", "success")
    return redirect(url_for("files.details", file_id=file_id))


@files_bp.route("/versions/<int:version_id>/restore", methods=["POST"])
@login_required
def restore_version(version_id: int):
    version = FileVersion.query.get_or_404(version_id)
    f_model = version.file
    if f_model.owner_id != current_user.id and not current_user.is_admin:
        abort(403)

    # Snapshot current state
    snapshot = FileVersion(
        file_id=f_model.id,
        stored_filename=f_model.stored_filename,
        mime_type=f_model.mime_type,
        size_bytes=f_model.size_bytes,
        sha256_hash=f_model.sha256_hash,
        created_by_id=current_user.id,
    )
    db.session.add(snapshot)

    # Restore from selected version
    f_model.stored_filename = version.stored_filename
    f_model.mime_type = version.mime_type
    f_model.size_bytes = version.size_bytes
    f_model.sha256_hash = version.sha256_hash
    f_model.last_accessed_at = datetime.utcnow()
    db.session.commit()
    log_event("file_restore_version", f"Restored version {version.id} for file {f_model.id}", user=current_user, file=f_model)
    flash("Version restored.", "success")
    return redirect(url_for("files.details", file_id=f_model.id))


@files_bp.route("/preview/<int:file_id>")
@login_required
def preview(file_id: int):
    f_model = File.query.get_or_404(file_id)
    if not _check_file_access(f_model):
        abort(403)

    storage_path = os.path.join(current_app.config["STORAGE_DIR"], f_model.stored_filename)
    if not os.path.exists(storage_path):
        flash("File not found on server.", "danger")
        abort(404)

    with open(storage_path, "rb") as f:
        encrypted_bytes = f.read()
    plaintext = decrypt_file_bytes(encrypted_bytes, associated_data=f_model.original_filename.encode())

    text_preview = None
    is_image = f_model.mime_type and f_model.mime_type.startswith("image/")
    is_pdf = f_model.mime_type == "application/pdf"
    if f_model.mime_type and f_model.mime_type.startswith("text/"):
        try:
            text_preview = plaintext.decode("utf-8", errors="replace")
        except Exception:
            text_preview = None

    return render_template(
        "preview.html",
        file=f_model,
        is_image=is_image,
        is_pdf=is_pdf,
        text_preview=text_preview,
    )


@files_bp.route("/raw/<int:file_id>")
@login_required
def raw(file_id: int):
    f_model = File.query.get_or_404(file_id)
    if not _check_file_access(f_model):
        abort(403)

    storage_path = os.path.join(current_app.config["STORAGE_DIR"], f_model.stored_filename)
    if not os.path.exists(storage_path):
        abort(404)

    with open(storage_path, "rb") as f:
        encrypted_bytes = f.read()
    plaintext = decrypt_file_bytes(encrypted_bytes, associated_data=f_model.original_filename.encode())

    return send_file(
        BytesIO(plaintext),
        as_attachment=False,
        download_name=f_model.original_filename,
        mimetype=f_model.mime_type or "application/octet-stream",
    )

