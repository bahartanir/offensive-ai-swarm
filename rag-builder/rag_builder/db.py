"""SQLite database layer for chunk/document metadata and FTS5 keyword search."""

import json
import sqlite3
from pathlib import Path

SCHEMA_VERSION = "1"
MODEL_NAME = "all-MiniLM-L6-v2"

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS documents (
    id           INTEGER PRIMARY KEY,
    source_repo  TEXT NOT NULL,
    file_path    TEXT NOT NULL,
    content      TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    indexed_at   TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(source_repo, file_path)
);

CREATE TABLE IF NOT EXISTS chunks (
    id             INTEGER PRIMARY KEY,
    content_hash   TEXT NOT NULL UNIQUE,
    content        TEXT NOT NULL,
    section_header TEXT,
    domain_tags    TEXT NOT NULL DEFAULT '[]',
    tag_source     TEXT NOT NULL DEFAULT 'auto',
    token_count    INTEGER NOT NULL,
    created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS chunk_instances (
    id              INTEGER PRIMARY KEY,
    chunk_id        INTEGER NOT NULL REFERENCES chunks(id),
    document_id     INTEGER NOT NULL REFERENCES documents(id),
    section_header  TEXT,
    chunk_index     INTEGER NOT NULL DEFAULT 0,
    UNIQUE(chunk_id, document_id, chunk_index)
);

CREATE TABLE IF NOT EXISTS repos (
    url          TEXT PRIMARY KEY,
    domain_tags  TEXT NOT NULL DEFAULT '[]',
    file_count   INTEGER NOT NULL DEFAULT 0,
    chunk_count  INTEGER NOT NULL DEFAULT 0,
    ingested_at  TEXT NOT NULL DEFAULT (datetime('now')),
    status       TEXT NOT NULL DEFAULT 'ok'
);

CREATE VIRTUAL TABLE IF NOT EXISTS chunks_fts USING fts5(
    content, section_header,
    content='chunks', content_rowid='id'
);

CREATE TRIGGER IF NOT EXISTS chunks_ai AFTER INSERT ON chunks BEGIN
    INSERT INTO chunks_fts(rowid, content, section_header)
    VALUES (new.id, new.content, new.section_header);
END;

CREATE TRIGGER IF NOT EXISTS chunks_ad AFTER DELETE ON chunks BEGIN
    INSERT INTO chunks_fts(chunks_fts, rowid, content, section_header)
    VALUES ('delete', old.id, old.content, old.section_header);
END;

CREATE TRIGGER IF NOT EXISTS chunks_au AFTER UPDATE ON chunks BEGIN
    INSERT INTO chunks_fts(chunks_fts, rowid, content, section_header)
    VALUES ('delete', old.id, old.content, old.section_header);
    INSERT INTO chunks_fts(rowid, content, section_header)
    VALUES (new.id, new.content, new.section_header);
END;
"""


class Database:
    """SQLite database for RAG metadata, document storage, and FTS5 search."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path))
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self._init_schema()

    def _init_schema(self):
        self.conn.executescript(SCHEMA_SQL)
        existing = self.conn.execute("SELECT COUNT(*) FROM schema_meta").fetchone()[0]
        if existing == 0:
            meta = {
                "schema_version": SCHEMA_VERSION,
                "model_name": MODEL_NAME,
                "model_version": "v2",
                "chunker_version": "1",
            }
            for key, value in meta.items():
                self.conn.execute(
                    "INSERT INTO schema_meta (key, value) VALUES (?, ?)",
                    (key, value),
                )
            self.conn.commit()
        else:
            stored = self.get_meta("schema_version")
            if stored != SCHEMA_VERSION:
                self.close()
                msg = (
                    f"schema version mismatch: expected {SCHEMA_VERSION}, "
                    f"got {stored}. Run rebuild to upgrade."
                )
                raise RuntimeError(msg)

    def execute(self, sql, params=()):
        return self.conn.execute(sql, params)

    def get_meta(self, key: str) -> str | None:
        row = self.conn.execute("SELECT value FROM schema_meta WHERE key = ?", (key,)).fetchone()
        return row[0] if row else None

    def insert_document(
        self,
        source_repo: str,
        file_path: str,
        content: str,
        content_hash: str,
    ) -> int:
        self.conn.execute(
            """INSERT INTO documents
               (source_repo, file_path, content, content_hash)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(source_repo, file_path)
               DO UPDATE SET content=excluded.content,
                             content_hash=excluded.content_hash,
                             indexed_at=datetime('now')""",
            (source_repo, file_path, content, content_hash),
        )
        self.conn.commit()
        row = self.conn.execute(
            "SELECT id FROM documents WHERE source_repo=? AND file_path=?",
            (source_repo, file_path),
        ).fetchone()
        return row[0]

    def get_document(self, doc_id: int) -> sqlite3.Row | None:
        return self.conn.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()

    def insert_chunk(
        self,
        content_hash: str,
        content: str,
        section_header: str | None,
        domain_tags: list[str],
        tag_source: str,
        token_count: int,
    ) -> tuple[int, bool]:
        """Insert a chunk. Returns (chunk_id, is_new).

        If content_hash already exists, returns existing ID
        with is_new=False.
        """
        tags_json = json.dumps(domain_tags)
        try:
            cursor = self.conn.execute(
                """INSERT INTO chunks
                   (content_hash, content, section_header,
                    domain_tags, tag_source, token_count)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    content_hash,
                    content,
                    section_header,
                    tags_json,
                    tag_source,
                    token_count,
                ),
            )
            self.conn.commit()
            return cursor.lastrowid, True
        except sqlite3.IntegrityError:
            row = self.conn.execute(
                "SELECT id FROM chunks WHERE content_hash = ?",
                (content_hash,),
            ).fetchone()
            return row[0], False

    def get_chunk(self, chunk_id: int) -> sqlite3.Row | None:
        return self.conn.execute("SELECT * FROM chunks WHERE id = ?", (chunk_id,)).fetchone()

    def get_all_chunk_ids(self) -> list[int]:
        rows = self.conn.execute("SELECT id FROM chunks").fetchall()
        return [row[0] for row in rows]

    def insert_instance(
        self,
        chunk_id: int,
        document_id: int,
        section_header: str | None,
        chunk_index: int,
    ) -> int:
        cursor = self.conn.execute(
            """INSERT OR IGNORE INTO chunk_instances
               (chunk_id, document_id, section_header, chunk_index)
               VALUES (?, ?, ?, ?)""",
            (chunk_id, document_id, section_header, chunk_index),
        )
        self.conn.commit()
        return cursor.lastrowid

    def remove_instances_for_document(self, document_id: int):
        self.conn.execute(
            "DELETE FROM chunk_instances WHERE document_id = ?",
            (document_id,),
        )
        self.conn.commit()

    def garbage_collect_chunks(self) -> list[int]:
        """Delete chunks with no remaining instances. Returns removed IDs."""
        orphans = self.conn.execute(
            """SELECT c.id FROM chunks c
               LEFT JOIN chunk_instances ci ON ci.chunk_id = c.id
               WHERE ci.id IS NULL"""
        ).fetchall()
        removed_ids = [row[0] for row in orphans]
        if removed_ids:
            placeholders = ",".join("?" * len(removed_ids))
            self.conn.execute(
                f"DELETE FROM chunks WHERE id IN ({placeholders})",
                removed_ids,
            )
            self.conn.commit()
        return removed_ids

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self):
        self.conn.close()
