import os
import sqlite3

from flask import current_app


def ensure_sqlite_schema() -> None:
    """
    Lightweight SQLite schema upgrader so existing secureshare.db keeps working
    without requiring manual migrations.
    """
    uri = current_app.config.get("SQLALCHEMY_DATABASE_URI", "")
    if not uri.startswith("sqlite:///"):
        return

    db_path = uri.replace("sqlite:///", "", 1)
    if not db_path:
        return

    # Resolve relative path from current working directory
    db_path = os.path.abspath(db_path)

    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()

        # Folders table
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS folders (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              owner_id INTEGER NOT NULL,
              name VARCHAR(255) NOT NULL,
              created_at DATETIME NOT NULL,
              is_deleted BOOLEAN NOT NULL DEFAULT 0,
              FOREIGN KEY(owner_id) REFERENCES users(id)
            )
            """
        )

        # Add missing columns to files table (SQLite supports ADD COLUMN)
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='files'")
        has_files = cur.fetchone() is not None
        if not has_files:
            return

        cur.execute("PRAGMA table_info(files)")
        existing_cols = {row[1] for row in cur.fetchall()}

        columns_to_add = [
            ("is_deleted", "ALTER TABLE files ADD COLUMN is_deleted BOOLEAN NOT NULL DEFAULT 0"),
            ("is_starred", "ALTER TABLE files ADD COLUMN is_starred BOOLEAN NOT NULL DEFAULT 0"),
            ("last_accessed_at", "ALTER TABLE files ADD COLUMN last_accessed_at DATETIME"),
            ("folder_id", "ALTER TABLE files ADD COLUMN folder_id INTEGER"),
        ]

        for col_name, ddl in columns_to_add:
            if col_name not in existing_cols:
                cur.execute(ddl)

        # File versions table
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS file_versions (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              file_id INTEGER NOT NULL,
              stored_filename VARCHAR(255) NOT NULL,
              mime_type VARCHAR(128),
              size_bytes INTEGER NOT NULL,
              sha256_hash VARCHAR(64) NOT NULL,
              created_at DATETIME NOT NULL,
              created_by_id INTEGER,
              FOREIGN KEY(file_id) REFERENCES files(id),
              FOREIGN KEY(created_by_id) REFERENCES users(id)
            )
            """
        )

        # Comments table
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS comments (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              file_id INTEGER NOT NULL,
              user_id INTEGER NOT NULL,
              content TEXT NOT NULL,
              created_at DATETIME NOT NULL,
              FOREIGN KEY(file_id) REFERENCES files(id),
              FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """
        )

        conn.commit()
    finally:
        conn.close()

