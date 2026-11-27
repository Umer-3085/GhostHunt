"""
GhostHunt — SQLite Data Access Layer & Foundation Module
Authoritative SQLite DAL with strict historical retention, fail-safe finding
classification, and controlled persistence baseline lifecycle management.

Architecture & Invariants:
- Per-operation SQLite connections with context management.
- WAL (Write-Ahead Logging) journal mode configured during initialization.
- Enforced foreign keys (PRAGMA foreign_keys = ON;) on every connection.
- Documented busy timeout (PRAGMA busy_timeout = 5000;) on every connection.
- Restrictive foreign-key deletes (ON DELETE RESTRICT) for historical integrity.
- Composite primary key on persistence_baseline (entry_type, entry_key, is_candidate)
  allowing identical keys across categories while rejecting snapshot duplicates.
- Strict scan lifecycle state transitions (IN_PROGRESS -> COMPLETED or FAILED).
- Fail-safe finding classification invariant:
    finding_type == 'diagnostic' => score_eligible == 0
- Controlled persistence baseline states:
    NOT_INITIALIZED -> CANDIDATE_REVIEW -> ACCEPTED_TRUSTED (or ENUMERATION_FAILED)
"""

import contextlib
import json
import logging
import math
import sqlite3
from typing import Any, Dict, Generator, List, Optional, Union

import config

logger = logging.getLogger("ghosthunt.db")

# Valid persistence categories tracked by the baseline subsystem
VALID_CATEGORIES = tuple(config.PERSISTENCE_CATEGORIES)

# Valid baseline states
BASELINE_STATES = ("NOT_INITIALIZED", "CANDIDATE_REVIEW", "ACCEPTED_TRUSTED", "ENUMERATION_FAILED")

# Valid signal types
VALID_SIGNALS = ("process_view", "persistence", "signature")

# Valid severity levels
VALID_SEVERITIES = ("low", "medium", "high")

# Valid finding classifications
VALID_FINDING_TYPES = ("threat", "diagnostic")

# Valid signature verification statuses
VALID_SIGNATURE_STATUSES = ("VALID", "UNSIGNED", "INVALID", "ERROR", "N/A")

# Valid scan history execution statuses
VALID_SCAN_STATUSES = ("IN_PROGRESS", "COMPLETED", "FAILED")


# ---------------------------------------------------------------------------
# Connection Management
# ---------------------------------------------------------------------------
@contextlib.contextmanager
def get_connection(db_path: Optional[str] = None) -> Generator[sqlite3.Connection, None, None]:
    """
    Context manager providing a per-operation SQLite connection.
    Enforces foreign keys and busy timeout on every connection.
    Automatically commits on normal completion or rolls back on exceptions.
    Note: WAL journal mode is configured once during init_db, not repeatedly here.
    """
    path = db_path or config.DB_PATH
    try:
        conn = sqlite3.connect(path, timeout=config.DB_BUSY_TIMEOUT_MS / 1000.0)
    except sqlite3.Error as err:
        logger.error("Failed to connect to SQLite database at '%s': %s", path, err)
        raise

    conn.row_factory = sqlite3.Row

    try:
        # Enforce SQLite engine pragmas per-connection
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute(f"PRAGMA busy_timeout = {config.DB_BUSY_TIMEOUT_MS};")

        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Database Schema Initialization (Idempotent & Migratable)
# ---------------------------------------------------------------------------
def init_db(db_path: Optional[str] = None) -> None:
    """
    Idempotently creates all required tables, constraints, and indexes.
    Enables and verifies WAL journal mode on the database file.
    Performs safe migration if an older single-column PK persistence_baseline exists.
    Seeds the per-category baseline metadata table for all categories.
    Handles initialization failures explicitly with structured error logging.
    """
    target_path = db_path or config.DB_PATH
    try:
        # 1. Enable and verify WAL mode during database initialization
        setup_conn = sqlite3.connect(target_path, timeout=config.DB_BUSY_TIMEOUT_MS / 1000.0)
        try:
            setup_conn.execute("PRAGMA foreign_keys = ON;")
            setup_conn.execute(f"PRAGMA busy_timeout = {config.DB_BUSY_TIMEOUT_MS};")
            wal_row = setup_conn.execute("PRAGMA journal_mode = WAL;").fetchone()
            current_journal = wal_row[0].lower() if wal_row else "unknown"

            # In-memory databases do not support WAL mode; file databases must be in WAL
            if target_path != ":memory:" and not target_path.startswith("file::memory:"):
                if current_journal != "wal":
                    raise RuntimeError(
                        f"Failed to configure WAL mode on '{target_path}'. Current journal_mode: '{current_journal}'"
                    )
        finally:
            setup_conn.close()

        # 2. Initialize tables and constraints
        with get_connection(target_path) as conn:
            # 1. Scan execution audit log
            conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                status TEXT NOT NULL CHECK(status IN ('IN_PROGRESS', 'COMPLETED', 'FAILED')),
                total_findings INTEGER DEFAULT 0,
                high_risk_count INTEGER DEFAULT 0,
                scan_duration_ms REAL DEFAULT 0.0,
                cache_hits INTEGER DEFAULT 0,
                cache_misses INTEGER DEFAULT 0,
                error_message TEXT DEFAULT NULL
            );
            """)

            # 2. Findings tied to a specific scan_id (fail-safe classification: explicit fields, no defaults)
            conn.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                pid INTEGER,
                process_name TEXT NOT NULL,
                signal TEXT NOT NULL CHECK(signal IN ('process_view', 'persistence', 'signature')),
                evidence TEXT NOT NULL,
                severity TEXT NOT NULL CHECK(severity IN ('low', 'medium', 'high')),
                finding_type TEXT NOT NULL CHECK(finding_type IN ('threat', 'diagnostic')),
                score_eligible INTEGER NOT NULL CHECK(score_eligible IN (0, 1)),
                signature_status TEXT DEFAULT 'N/A' CHECK(signature_status IN ('VALID', 'UNSIGNED', 'INVALID', 'ERROR', 'N/A')),
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                metadata TEXT DEFAULT '{}',
                FOREIGN KEY(scan_id) REFERENCES scan_history(id) ON DELETE RESTRICT,
                CHECK (
                    (finding_type = 'diagnostic' AND score_eligible = 0) OR
                    (finding_type = 'threat' AND score_eligible IN (0, 1))
                )
            );
            """)

            # 3. Risk scores calculated for a specific scan_id (strict retention)
            conn.execute("""
            CREATE TABLE IF NOT EXISTS risk_scores (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                item_key TEXT NOT NULL,
                pid INTEGER,
                process_name TEXT NOT NULL,
                score REAL NOT NULL CHECK(score >= 0.0 AND score <= 1.0),
                risk_level TEXT NOT NULL CHECK(risk_level IN ('LOW', 'MEDIUM', 'HIGH')),
                signals_triggered TEXT NOT NULL,
                calculated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(scan_id, item_key),
                FOREIGN KEY(scan_id) REFERENCES scan_history(id) ON DELETE RESTRICT
            );
            """)

            # 4. Per-category baseline metadata (candidate review & accepted reference state)
            conn.execute("""
            CREATE TABLE IF NOT EXISTS persistence_baseline_meta (
                category TEXT PRIMARY KEY CHECK(category IN ('registry', 'task', 'service')),
                baseline_state TEXT NOT NULL DEFAULT 'NOT_INITIALIZED' CHECK(baseline_state IN ('NOT_INITIALIZED', 'CANDIDATE_REVIEW', 'ACCEPTED_TRUSTED', 'ENUMERATION_FAILED')),
                candidate_captured_at DATETIME DEFAULT NULL,
                accepted_at DATETIME DEFAULT NULL,
                last_reset_at DATETIME DEFAULT NULL,
                candidate_entry_count INTEGER NOT NULL DEFAULT 0,
                accepted_entry_count INTEGER NOT NULL DEFAULT 0,
                last_enumeration_status TEXT DEFAULT 'PENDING' CHECK(last_enumeration_status IN ('PENDING', 'SUCCESS', 'FAILED')),
                last_error TEXT DEFAULT NULL
            );
            """)

            # Safe schema migration for persistence_baseline:
            # Verify primary key structure; if table exists with old single-column PK, migrate safely.
            table_info = conn.execute("PRAGMA table_info(persistence_baseline);").fetchall()
            if table_info:
                pk_cols = [r["name"] for r in table_info if r["pk"] > 0]
                if set(pk_cols) != {"entry_type", "entry_key", "is_candidate"}:
                    logger.info("Upgrading persistence_baseline to composite primary key (entry_type, entry_key, is_candidate)")
                    conn.execute("ALTER TABLE persistence_baseline RENAME TO persistence_baseline_legacy;")

                    # Explicit conflict detection before migration to prevent silent record loss
                    dup_rows = conn.execute("""
                        SELECT entry_type, entry_key, is_candidate, COUNT(*) AS cnt
                        FROM persistence_baseline_legacy
                        GROUP BY entry_type, entry_key, is_candidate
                        HAVING cnt > 1;
                    """).fetchall()
                    if dup_rows:
                        dup_details = [
                            f"({r['entry_type']}, {r['entry_key']}, is_candidate={r['is_candidate']}): count={r['cnt']}"
                            for r in dup_rows
                        ]
                        raise RuntimeError(
                            f"Legacy migration conflict: duplicate primary keys found in persistence_baseline_legacy: {dup_details}. "
                            "Migration aborted to prevent silent record loss."
                        )

                    invalid_cnt = conn.execute("""
                        SELECT COUNT(*) AS cnt
                        FROM persistence_baseline_legacy
                        WHERE entry_type NOT IN ('registry', 'task', 'service')
                           OR is_candidate NOT IN (0, 1);
                    """).fetchone()["cnt"]
                    if invalid_cnt > 0:
                        raise RuntimeError(
                            f"Legacy migration conflict: found {invalid_cnt} records with invalid entry_type or is_candidate in persistence_baseline_legacy. "
                            "Migration aborted to prevent silent record loss."
                        )

                    legacy_count = conn.execute("SELECT COUNT(*) AS cnt FROM persistence_baseline_legacy;").fetchone()["cnt"]

                    conn.execute("""
                    CREATE TABLE persistence_baseline (
                        entry_type TEXT NOT NULL CHECK(entry_type IN ('registry', 'task', 'service')),
                        entry_key TEXT NOT NULL,
                        entry_value TEXT NOT NULL,
                        fingerprint TEXT NOT NULL,
                        structured_data TEXT NOT NULL DEFAULT '{}',
                        is_candidate INTEGER NOT NULL CHECK(is_candidate IN (0, 1)),
                        captured_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        accepted_at DATETIME DEFAULT NULL,
                        PRIMARY KEY (entry_type, entry_key, is_candidate)
                    );
                    """)

                    cursor = conn.execute("""
                    INSERT INTO persistence_baseline (
                        entry_type, entry_key, entry_value, fingerprint, structured_data, is_candidate, captured_at, accepted_at
                    )
                    SELECT entry_type, entry_key, entry_value, fingerprint, structured_data, is_candidate, captured_at, accepted_at
                    FROM persistence_baseline_legacy;
                    """)

                    if cursor.rowcount != legacy_count:
                        raise RuntimeError(
                            f"Legacy migration row mismatch: expected {legacy_count} rows, migrated {cursor.rowcount}. "
                            "Migration aborted to prevent silent record loss."
                        )

                    conn.execute("DROP TABLE persistence_baseline_legacy;")
            else:
                # 5. Structured baseline persistence entries (composite primary key)
                conn.execute("""
                CREATE TABLE IF NOT EXISTS persistence_baseline (
                    entry_type TEXT NOT NULL CHECK(entry_type IN ('registry', 'task', 'service')),
                    entry_key TEXT NOT NULL,
                    entry_value TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    structured_data TEXT NOT NULL DEFAULT '{}',
                    is_candidate INTEGER NOT NULL CHECK(is_candidate IN (0, 1)),
                    captured_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    accepted_at DATETIME DEFAULT NULL,
                    PRIMARY KEY (entry_type, entry_key, is_candidate)
                );
                """)

            # Indexes for rapid scan-scoped and category-scoped retrieval
            conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_pid ON findings(pid);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_score_eligible ON findings(score_eligible);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_type ON findings(finding_type);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_risk_scores_scan_id ON risk_scores(scan_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_risk_scores_item_key ON risk_scores(item_key);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_history_status ON scan_history(status);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_baseline_lookup ON persistence_baseline(entry_type, is_candidate);")

            # Seed metadata rows for all categories idempotently
            for cat in VALID_CATEGORIES:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO persistence_baseline_meta (
                        category, baseline_state, candidate_entry_count, accepted_entry_count
                    ) VALUES (?, 'NOT_INITIALIZED', 0, 0);
                    """,
                    (cat,),
                )

        logger.info("Database initialized successfully at '%s'", target_path)
    except Exception as exc:
        logger.error("Failed to initialize database: %s", exc, exc_info=True)
        raise


# ---------------------------------------------------------------------------
# Finding Validation & Pre-Insert Safeguards
# ---------------------------------------------------------------------------
def validate_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validates a raw finding dictionary against the authoritative contract.
    Enforces:
    - process_name and evidence must be non-empty strings (not None or other types).
    - scan_id and pid must be strict integers (rejecting booleans).
    - metadata must be a valid dict or a valid JSON string (parsed and validated).
    - Enforces the core classification invariant:
        finding_type == 'diagnostic' => score_eligible == 0
    - Rejects missing fields, invalid types, or contradictory classification states.

    Returns a normalized finding dictionary suitable for SQL insertion.
    """
    if not isinstance(finding, dict):
        raise TypeError(f"Finding must be a dictionary, got {type(finding).__name__}")

    # Check mandatory fields
    required_fields = {
        "scan_id",
        "process_name",
        "signal",
        "evidence",
        "severity",
        "finding_type",
        "score_eligible",
    }
    missing = required_fields - set(finding.keys())
    if missing:
        raise ValueError(f"Finding missing mandatory fields: {missing}")

    # Validate scan_id: strict integer > 0 (rejecting booleans)
    scan_id = finding["scan_id"]
    if isinstance(scan_id, bool) or not isinstance(scan_id, int) or scan_id <= 0:
        raise ValueError(f"scan_id must be a positive integer, got {scan_id!r} (type {type(scan_id).__name__})")

    # Validate process_name: actual non-empty string
    raw_process_name = finding["process_name"]
    if not isinstance(raw_process_name, str) or not raw_process_name.strip():
        raise ValueError(
            f"process_name must be a non-empty string, got {raw_process_name!r} (type {type(raw_process_name).__name__})"
        )
    process_name = raw_process_name.strip()

    # Validate pid: strict integer >= 0 or None (rejecting booleans)
    pid = finding.get("pid")
    if pid is not None:
        if isinstance(pid, bool) or not isinstance(pid, int) or pid < 0:
            raise ValueError(f"pid must be an integer >= 0 or None, got {pid!r} (type {type(pid).__name__})")

    # Validate signal
    signal = finding["signal"]
    if signal not in VALID_SIGNALS:
        raise ValueError(f"Invalid signal '{signal}', must be one of {VALID_SIGNALS}")

    # Validate evidence: actual non-empty string
    raw_evidence = finding["evidence"]
    if not isinstance(raw_evidence, str) or not raw_evidence.strip():
        raise ValueError(
            f"evidence must be a non-empty string, got {raw_evidence!r} (type {type(raw_evidence).__name__})"
        )
    evidence = raw_evidence.strip()

    # Validate severity
    severity = finding["severity"]
    if severity not in VALID_SEVERITIES:
        raise ValueError(f"Invalid severity '{severity}', must be one of {VALID_SEVERITIES}")

    # Validate finding_type
    finding_type = finding["finding_type"]
    if finding_type not in VALID_FINDING_TYPES:
        raise ValueError(f"Invalid finding_type '{finding_type}', must be one of {VALID_FINDING_TYPES}")

    # Normalize and validate score_eligible: explicit boolean or 0/1
    raw_eligible = finding["score_eligible"]
    if isinstance(raw_eligible, bool):
        score_eligible = 1 if raw_eligible else 0
    elif isinstance(raw_eligible, int) and not isinstance(raw_eligible, bool) and raw_eligible in (0, 1):
        score_eligible = raw_eligible
    else:
        raise ValueError(f"score_eligible must be boolean or 0/1, got {raw_eligible!r}")

    # Enforce classification invariant: diagnostic findings MUST NEVER be score eligible
    if finding_type == "diagnostic" and score_eligible != 0:
        raise ValueError(
            "Classification invariant violated: finding_type='diagnostic' must have score_eligible=0"
        )

    # Optional signature status validation
    sig_status = finding.get("signature_status", "N/A")
    if sig_status not in VALID_SIGNATURE_STATUSES:
        raise ValueError(f"Invalid signature_status '{sig_status}', must be one of {VALID_SIGNATURE_STATUSES}")

    # Validate metadata: reject invalid JSON strings or unsupported types
    raw_meta = finding.get("metadata")
    if raw_meta is None:
        meta_json = "{}"
    elif isinstance(raw_meta, dict):
        try:
            meta_json = json.dumps(raw_meta)
        except (TypeError, ValueError) as err:
            raise ValueError(f"Failed to serialize metadata dict to JSON: {err}")
    elif isinstance(raw_meta, str):
        try:
            parsed = json.loads(raw_meta)
            if not isinstance(parsed, (dict, list)):
                raise ValueError("Parsed metadata JSON must be an object or array")
            meta_json = raw_meta
        except (json.JSONDecodeError, ValueError) as err:
            raise ValueError(f"Invalid metadata JSON string: {err}")
    else:
        raise TypeError(f"Unsupported metadata type: {type(raw_meta).__name__}; must be dict, JSON str, or None")

    return {
        "scan_id": scan_id,
        "pid": pid,
        "process_name": process_name,
        "signal": signal,
        "evidence": evidence,
        "severity": severity,
        "finding_type": finding_type,
        "score_eligible": score_eligible,
        "signature_status": sig_status,
        "metadata": meta_json,
    }


# ---------------------------------------------------------------------------
# Scan Lifecycle Management
# ---------------------------------------------------------------------------
def start_scan(db_path: Optional[str] = None) -> int:
    """
    Creates an IN_PROGRESS scan record in scan_history.
    Returns the newly generated scan_id.
    """
    with get_connection(db_path) as conn:
        cursor = conn.execute(
            """
            INSERT INTO scan_history (status)
            VALUES ('IN_PROGRESS');
            """
        )
        scan_id = cursor.lastrowid
        if scan_id is None:
            raise RuntimeError("Failed to generate scan_id during start_scan")
        return int(scan_id)


def complete_scan(
    scan_id: int,
    total_findings: int,
    high_risk_count: int,
    duration_ms: float,
    cache_hits: int = 0,
    cache_misses: int = 0,
    db_path: Optional[str] = None,
) -> None:
    """
    Marks an IN_PROGRESS scan as COMPLETED, updating execution metrics.
    Enforces valid state transition: only IN_PROGRESS -> COMPLETED is permitted.
    Rejects updating completed, failed, or nonexistent scans.
    Validates non-negative counts and finite non-negative duration.
    """
    if isinstance(scan_id, bool) or not isinstance(scan_id, int) or scan_id <= 0:
        raise ValueError(f"scan_id must be a positive integer, got {scan_id!r}")
    if isinstance(total_findings, bool) or not isinstance(total_findings, int) or total_findings < 0:
        raise ValueError(f"total_findings must be an integer >= 0, got {total_findings!r}")
    if isinstance(high_risk_count, bool) or not isinstance(high_risk_count, int) or high_risk_count < 0:
        raise ValueError(f"high_risk_count must be an integer >= 0, got {high_risk_count!r}")
    if isinstance(cache_hits, bool) or not isinstance(cache_hits, int) or cache_hits < 0:
        raise ValueError(f"cache_hits must be an integer >= 0, got {cache_hits!r}")
    if isinstance(cache_misses, bool) or not isinstance(cache_misses, int) or cache_misses < 0:
        raise ValueError(f"cache_misses must be an integer >= 0, got {cache_misses!r}")
    if not isinstance(duration_ms, (int, float)) or not math.isfinite(duration_ms) or duration_ms < 0.0:
        raise ValueError(f"duration_ms must be a finite number >= 0.0, got {duration_ms!r}")

    with get_connection(db_path) as conn:
        # Check current scan existence and status
        row = conn.execute("SELECT status FROM scan_history WHERE id = ?;", (scan_id,)).fetchone()
        if not row:
            raise ValueError(f"Scan {scan_id} does not exist")
        if row["status"] != "IN_PROGRESS":
            raise ValueError(f"Cannot complete scan {scan_id}: current status is '{row['status']}', expected 'IN_PROGRESS'")

        cursor = conn.execute(
            """
            UPDATE scan_history
            SET status = 'COMPLETED',
                total_findings = ?,
                high_risk_count = ?,
                scan_duration_ms = ?,
                cache_hits = ?,
                cache_misses = ?
            WHERE id = ? AND status = 'IN_PROGRESS';
            """,
            (total_findings, high_risk_count, float(duration_ms), cache_hits, cache_misses, scan_id),
        )
        if cursor.rowcount != 1:
            raise RuntimeError(f"Conditional update failed: scan {scan_id} could not be transitioned to COMPLETED")


def fail_scan(
    scan_id: int,
    error_message: str,
    duration_ms: float = 0.0,
    db_path: Optional[str] = None,
) -> None:
    """
    Marks an IN_PROGRESS scan as FAILED with error details.
    Enforces valid state transition: only IN_PROGRESS -> FAILED is permitted.
    Rejects updating completed, failed, or nonexistent scans.
    """
    if isinstance(scan_id, bool) or not isinstance(scan_id, int) or scan_id <= 0:
        raise ValueError(f"scan_id must be a positive integer, got {scan_id!r}")
    if not isinstance(error_message, str) or not error_message.strip():
        raise ValueError("error_message must be a non-empty string")
    if not isinstance(duration_ms, (int, float)) or not math.isfinite(duration_ms) or duration_ms < 0.0:
        raise ValueError(f"duration_ms must be a finite number >= 0.0, got {duration_ms!r}")

    with get_connection(db_path) as conn:
        row = conn.execute("SELECT status FROM scan_history WHERE id = ?;", (scan_id,)).fetchone()
        if not row:
            raise ValueError(f"Scan {scan_id} does not exist")
        if row["status"] != "IN_PROGRESS":
            raise ValueError(f"Cannot fail scan {scan_id}: current status is '{row['status']}', expected 'IN_PROGRESS'")

        cursor = conn.execute(
            """
            UPDATE scan_history
            SET status = 'FAILED',
                error_message = ?,
                scan_duration_ms = ?
            WHERE id = ? AND status = 'IN_PROGRESS';
            """,
            (error_message.strip(), float(duration_ms), scan_id),
        )
        if cursor.rowcount != 1:
            raise RuntimeError(f"Conditional update failed: scan {scan_id} could not be transitioned to FAILED")


def get_scan_status(scan_id: int, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Retrieves the execution status and metadata for a specific scan_id.
    """
    with get_connection(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM scan_history WHERE id = ?;",
            (scan_id,),
        ).fetchone()
        return dict(row) if row else None


def get_latest_completed_scan_id(db_path: Optional[str] = None) -> Optional[int]:
    """
    Returns the maximum scan_id that completed successfully (status = 'COMPLETED').
    Ignores IN_PROGRESS and FAILED scans.
    """
    with get_connection(db_path) as conn:
        row = conn.execute(
            "SELECT MAX(id) AS latest_id FROM scan_history WHERE status = 'COMPLETED';"
        ).fetchone()
        if row and row["latest_id"] is not None:
            return int(row["latest_id"])
        return None


def get_scan_history(limit: int = 50, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Retrieves recent scan execution audit records for timeline analysis.
    """
    with get_connection(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM scan_history ORDER BY id DESC LIMIT ?;",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]


def get_recent_completed_scans(limit: int = 10, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Retrieves the last N completed scans with summary statistics and entity counts
    for the horizontal timeline card.
    """
    with get_connection(db_path) as conn:
        rows = conn.execute(
            """
            SELECT s.*,
                   COALESCE((SELECT COUNT(*) FROM risk_scores r WHERE r.scan_id = s.id), 0) AS entity_count,
                   COALESCE((SELECT COUNT(*) FROM risk_scores r WHERE r.scan_id = s.id AND r.risk_level = 'HIGH'), 0) AS high_count,
                   COALESCE((SELECT COUNT(*) FROM risk_scores r WHERE r.scan_id = s.id AND r.risk_level = 'MEDIUM'), 0) AS med_count,
                   COALESCE((SELECT COUNT(*) FROM risk_scores r WHERE r.scan_id = s.id AND r.risk_level = 'LOW'), 0) AS low_count
            FROM scan_history s
            WHERE s.status = 'COMPLETED'
            ORDER BY s.id DESC
            LIMIT ?;
            """,
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Findings Data Access Layer
# ---------------------------------------------------------------------------
def insert_findings(
    scan_id: int,
    findings: List[Dict[str, Any]],
    db_path: Optional[str] = None,
) -> int:
    """
    Validates and bulk-inserts findings for a specific scan_id.
    Rejects non-dict items and invalid or conflicting scan_ids before normalization.
    Operates inside an atomic transaction.
    Returns the number of findings inserted.
    """
    if isinstance(scan_id, bool) or not isinstance(scan_id, int) or scan_id <= 0:
        raise ValueError(f"scan_id must be a positive integer, got {scan_id!r}")
    if not isinstance(findings, list):
        raise TypeError(f"findings must be a list, got {type(findings).__name__}")
    if not findings:
        return 0

    validated_list = []
    for f in findings:
        if not isinstance(f, dict):
            raise TypeError(f"Each finding must be a dictionary, got {type(f).__name__}")

        # Check for and validate finding scan_id before normalization
        if "scan_id" in f and f["scan_id"] is not None:
            supplied_scan_id = f["scan_id"]
            if isinstance(supplied_scan_id, bool) or not isinstance(supplied_scan_id, int) or supplied_scan_id <= 0:
                raise ValueError(f"Finding scan_id must be a positive integer, got {supplied_scan_id!r}")
            if supplied_scan_id != scan_id:
                raise ValueError(
                    f"Finding scan_id ({supplied_scan_id}) conflicts with target scan_id ({scan_id})"
                )

        item = dict(f)
        item["scan_id"] = scan_id
        validated_list.append(validate_finding(item))

    with get_connection(db_path) as conn:
        conn.executemany(
            """
            INSERT INTO findings (
                scan_id, pid, process_name, signal, evidence,
                severity, finding_type, score_eligible, signature_status, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            [
                (
                    v["scan_id"],
                    v["pid"],
                    v["process_name"],
                    v["signal"],
                    v["evidence"],
                    v["severity"],
                    v["finding_type"],
                    v["score_eligible"],
                    v["signature_status"],
                    v["metadata"],
                )
                for v in validated_list
            ],
        )
        return len(validated_list)


def get_findings_for_scan(
    scan_id: int,
    include_diagnostics: bool = True,
    db_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Retrieves all findings for a given scan_id.
    Optionally filters out operational diagnostics when include_diagnostics=False.
    """
    with get_connection(db_path) as conn:
        if include_diagnostics:
            rows = conn.execute(
                "SELECT * FROM findings WHERE scan_id = ? ORDER BY id ASC;",
                (scan_id,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM findings WHERE scan_id = ? AND finding_type = 'threat' ORDER BY id ASC;",
                (scan_id,),
            ).fetchall()
        return [dict(r) for r in rows]


def get_findings_for_process(
    scan_id: int,
    pid: int,
    include_diagnostics: bool = True,
    db_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Retrieves findings for a specific process PID within a scan_id.
    """
    with get_connection(db_path) as conn:
        if include_diagnostics:
            rows = conn.execute(
                "SELECT * FROM findings WHERE scan_id = ? AND pid = ? ORDER BY id ASC;",
                (scan_id, pid),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM findings WHERE scan_id = ? AND pid = ? AND finding_type = 'threat' ORDER BY id ASC;",
                (scan_id, pid),
            ).fetchall()
        return [dict(r) for r in rows]


def get_system_findings(
    scan_id: int,
    include_diagnostics: bool = True,
    db_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Retrieves system-level findings (pid IS NULL) for a given scan_id.
    """
    with get_connection(db_path) as conn:
        if include_diagnostics:
            rows = conn.execute(
                "SELECT * FROM findings WHERE scan_id = ? AND pid IS NULL ORDER BY id ASC;",
                (scan_id,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM findings WHERE scan_id = ? AND pid IS NULL AND finding_type = 'threat' ORDER BY id ASC;",
                (scan_id,),
            ).fetchall()
        return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Risk Scores Data Access Layer
# ---------------------------------------------------------------------------
def insert_risk_scores(
    scan_id: int,
    risk_scores: List[Dict[str, Any]],
    db_path: Optional[str] = None,
) -> int:
    """
    Bulk-inserts risk score records for entities in a specific scan_id.
    Enforces:
    - Finite float score in [0.0, 1.0] (rejects NaN and infinity).
    - Risk level matches the configured thresholds:
        LOW: score < 0.40
        MEDIUM: 0.40 <= score < 0.60
        HIGH: score >= 0.60
    - Non-empty item_key and process_name.
    - Valid PID (strict integer >= 0 or None).
    Operates inside an atomic transaction.
    """
    if isinstance(scan_id, bool) or not isinstance(scan_id, int) or scan_id <= 0:
        raise ValueError(f"scan_id must be a positive integer, got {scan_id!r}")
    if not risk_scores:
        return 0

    validated = []
    for r in risk_scores:
        if not isinstance(r, dict):
            raise TypeError(f"Risk score entry must be a dictionary, got {type(r).__name__}")

        raw_key = r.get("item_key")
        if not isinstance(raw_key, str) or not raw_key.strip():
            raise ValueError(f"item_key must be a non-empty string, got {raw_key!r}")
        item_key = raw_key.strip()

        raw_proc = r.get("process_name")
        if not isinstance(raw_proc, str) or not raw_proc.strip():
            raise ValueError(f"process_name must be a non-empty string, got {raw_proc!r}")
        process_name = raw_proc.strip()

        raw_score = r.get("score")
        if (
            isinstance(raw_score, bool)
            or not isinstance(raw_score, (int, float))
            or not math.isfinite(raw_score)
        ):
            raise ValueError(f"score must be a finite float, got {raw_score!r}")
        score = float(raw_score)
        if score < 0.0 or score > 1.0:
            raise ValueError(f"Score must be between 0.0 and 1.0, got {score}")

        # Validate risk level against configured thresholds
        if score >= config.RISK_THRESHOLD_HIGH:
            expected_level = "HIGH"
        elif score >= config.RISK_THRESHOLD_MEDIUM:
            expected_level = "MEDIUM"
        else:
            expected_level = "LOW"

        risk_level = r.get("risk_level")
        if risk_level != expected_level:
            raise ValueError(
                f"Risk level '{risk_level}' does not match score {score:.4f} (expected '{expected_level}')"
            )

        pid = r.get("pid")
        if pid is not None:
            if isinstance(pid, bool) or not isinstance(pid, int) or pid < 0:
                raise ValueError(f"pid must be an integer >= 0 or None, got {pid!r}")

        signals = str(r.get("signals_triggered", ""))
        validated.append((scan_id, item_key, pid, process_name, score, risk_level, signals))

    with get_connection(db_path) as conn:
        conn.executemany(
            """
            INSERT INTO risk_scores (
                scan_id, item_key, pid, process_name, score, risk_level, signals_triggered
            ) VALUES (?, ?, ?, ?, ?, ?, ?);
            """,
            validated,
        )
        return len(validated)


def get_risk_scores_for_scan(
    scan_id: int,
    db_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Retrieves risk-ranked entities for a specific scan_id, ordered by score descending.
    """
    with get_connection(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM risk_scores WHERE scan_id = ? ORDER BY score DESC, item_key ASC;",
            (scan_id,),
        ).fetchall()
        return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Baseline Management & Atomic Operations
# ---------------------------------------------------------------------------
def get_category_baseline_meta(
    category: str,
    db_path: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """
    Retrieves metadata for a specific persistence category.
    """
    if category not in VALID_CATEGORIES:
        raise ValueError(f"Invalid category '{category}', must be one of {VALID_CATEGORIES}")

    with get_connection(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM persistence_baseline_meta WHERE category = ?;",
            (category,),
        ).fetchone()
        return dict(row) if row else None


def get_all_baseline_meta(db_path: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
    """
    Retrieves baseline metadata for all persistence categories.
    """
    with get_connection(db_path) as conn:
        rows = conn.execute("SELECT * FROM persistence_baseline_meta;").fetchall()
        return {r["category"]: dict(r) for r in rows}


def capture_candidate_baseline_atomic(
    category: str,
    entries: List[Dict[str, Any]],
    db_path: Optional[str] = None,
) -> int:
    """
    Atomically captures discovered persistence items as a candidate baseline (is_candidate = 1).
    Transitions the category to CANDIDATE_REVIEW.

    Security & Validation Safeguards:
    - Verifies the category metadata row exists in persistence_baseline_meta.
    - Rejects invalid lifecycle states: candidate capture cannot overwrite ACCEPTED_TRUSTED.
    - Validates required entry fields: entry_key and fingerprint must be non-empty strings.
    - Validates structured_data as valid JSON dict or valid JSON string.
    - Rejects duplicate entry_keys within the candidate snapshot.
    - Candidate replacement is atomic: failure rolls back and leaves previous snapshot intact.
    - Ensures metadata update affects exactly one row.
    """
    if category not in VALID_CATEGORIES:
        raise ValueError(f"Invalid category '{category}', must be one of {VALID_CATEGORIES}")

    # Validate all entries before database modification
    validated_entries = []
    seen_keys = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise TypeError(f"Baseline entry must be a dictionary, got {type(entry).__name__}")

        raw_key = entry.get("entry_key")
        if not isinstance(raw_key, str) or not raw_key.strip():
            raise ValueError(f"entry_key must be a non-empty string, got {raw_key!r}")
        entry_key = raw_key.strip()

        if entry_key in seen_keys:
            raise ValueError(
                f"Duplicate entry_key '{entry_key}' found in candidate entries for category '{category}'"
            )
        seen_keys.add(entry_key)

        raw_fp = entry.get("fingerprint")
        if not isinstance(raw_fp, str) or not raw_fp.strip():
            raise ValueError(f"fingerprint must be a non-empty string, got {raw_fp!r}")
        fingerprint = raw_fp.strip()

        entry_value = str(entry.get("entry_value", ""))

        raw_struct = entry.get("structured_data")
        if raw_struct is None:
            struct_json = "{}"
        elif isinstance(raw_struct, dict):
            try:
                struct_json = json.dumps(raw_struct)
            except (TypeError, ValueError) as err:
                raise ValueError(f"Failed to serialize structured_data to JSON: {err}")
        elif isinstance(raw_struct, str):
            try:
                parsed = json.loads(raw_struct)
                if not isinstance(parsed, (dict, list)):
                    raise ValueError("structured_data JSON must parse to an object or array")
                struct_json = raw_struct
            except (json.JSONDecodeError, ValueError) as err:
                raise ValueError(f"Invalid structured_data JSON string: {err}")
        else:
            raise TypeError(f"Unsupported structured_data type: {type(raw_struct).__name__}; must be dict, JSON str, or None")

        validated_entries.append((category, entry_key, entry_value, fingerprint, struct_json))

    with get_connection(db_path) as conn:
        # Check current metadata existence and lifecycle state
        meta = conn.execute(
            "SELECT baseline_state FROM persistence_baseline_meta WHERE category = ?;",
            (category,),
        ).fetchone()

        if not meta:
            raise ValueError(f"Category metadata row for '{category}' does not exist")

        if meta["baseline_state"] == "ACCEPTED_TRUSTED":
            raise ValueError(
                f"Category '{category}' is already ACCEPTED_TRUSTED. Candidate capture cannot overwrite an accepted baseline."
            )

        # Remove previous candidate entries for this category
        conn.execute(
            "DELETE FROM persistence_baseline WHERE entry_type = ? AND is_candidate = 1;",
            (category,),
        )

        # Insert fresh candidate entries
        conn.executemany(
            """
            INSERT INTO persistence_baseline (
                entry_type, entry_key, entry_value, fingerprint, structured_data, is_candidate
            ) VALUES (?, ?, ?, ?, ?, 1);
            """,
            validated_entries,
        )

        # Update metadata state to CANDIDATE_REVIEW
        cursor = conn.execute(
            """
            UPDATE persistence_baseline_meta
            SET baseline_state = 'CANDIDATE_REVIEW',
                candidate_captured_at = CURRENT_TIMESTAMP,
                candidate_entry_count = ?,
                last_enumeration_status = 'SUCCESS',
                last_error = NULL
            WHERE category = ?;
            """,
            (len(validated_entries), category),
        )

        if cursor.rowcount != 1:
            raise RuntimeError(f"Metadata update failed: expected 1 row affected for '{category}', got {cursor.rowcount}")

        logger.info(
            "Captured candidate baseline for '%s' with %d entries (state=CANDIDATE_REVIEW)",
            category,
            len(validated_entries),
        )
        return len(validated_entries)


def accept_baseline_atomic(
    category: Optional[str] = None,
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Atomically promotes candidate persistence records to ACCEPTED_TRUSTED reference status.

    Validation & Invariant Requirements:
    - Every category being accepted must have an existing metadata row.
    - Category must be in exactly CANDIDATE_REVIEW state.
    - Rejects attempts to accept from NOT_INITIALIZED, ENUMERATION_FAILED, or ACCEPTED_TRUSTED.
    - Validates that the actual count of candidate records in persistence_baseline matches
      the candidate_entry_count recorded in metadata.
    - Supports legitimate empty candidate inventory (candidate_entry_count == 0).
    - Validation, record promotion, and metadata updates execute within one single transaction.
    - Does not report successful acceptance if no valid state transition occurred.

    Returns summary of accepted categories and promoted entry count.
    """
    if category is not None and category not in VALID_CATEGORIES:
        raise ValueError(f"Invalid category '{category}', must be one of {VALID_CATEGORIES}")

    with get_connection(db_path) as conn:
        if category is not None:
            meta = conn.execute(
                "SELECT * FROM persistence_baseline_meta WHERE category = ?;",
                (category,),
            ).fetchone()
            if not meta:
                raise ValueError(f"Category metadata row for '{category}' does not exist")
            if meta["baseline_state"] != "CANDIDATE_REVIEW":
                raise ValueError(
                    f"Category '{category}' cannot be accepted: current state is '{meta['baseline_state']}', expected 'CANDIDATE_REVIEW'"
                )
            target_metas = [meta]
        else:
            target_metas = conn.execute(
                "SELECT * FROM persistence_baseline_meta WHERE baseline_state = 'CANDIDATE_REVIEW';"
            ).fetchall()
            if not target_metas:
                raise ValueError("No categories are in CANDIDATE_REVIEW state to accept")

        promoted_total = 0
        accepted_categories = []

        for meta_row in target_metas:
            cat = meta_row["category"]
            expected_count = meta_row["candidate_entry_count"]

            # Verify consistent candidate entry count
            actual_count = conn.execute(
                "SELECT COUNT(*) AS cnt FROM persistence_baseline WHERE entry_type = ? AND is_candidate = 1;",
                (cat,),
            ).fetchone()["cnt"]

            if actual_count != expected_count:
                raise ValueError(
                    f"Candidate entry count mismatch for '{cat}': metadata reports {expected_count}, but found {actual_count} records"
                )

            # Delete any prior accepted entries for this category before promotion
            conn.execute(
                "DELETE FROM persistence_baseline WHERE entry_type = ? AND is_candidate = 0;",
                (cat,),
            )

            # Promote candidate entries to accepted reference records
            cursor = conn.execute(
                """
                UPDATE persistence_baseline
                SET is_candidate = 0,
                    accepted_at = CURRENT_TIMESTAMP
                WHERE entry_type = ? AND is_candidate = 1;
                """,
                (cat,),
            )
            promoted_count = cursor.rowcount
            promoted_total += promoted_count

            # Update category metadata
            meta_cursor = conn.execute(
                """
                UPDATE persistence_baseline_meta
                SET baseline_state = 'ACCEPTED_TRUSTED',
                    accepted_at = CURRENT_TIMESTAMP,
                    accepted_entry_count = candidate_entry_count
                WHERE category = ? AND baseline_state = 'CANDIDATE_REVIEW';
                """,
                (cat,),
            )
            if meta_cursor.rowcount != 1:
                raise RuntimeError(f"Failed to update metadata for category '{cat}' to ACCEPTED_TRUSTED")

            accepted_categories.append(cat)
            logger.info("Category '%s' accepted as trusted baseline (%d entries promoted)", cat, promoted_count)

        return {
            "accepted_categories": accepted_categories,
            "promoted_entries": promoted_total,
        }


def record_enumeration_failure(
    category: str,
    error_message: str,
    db_path: Optional[str] = None,
) -> None:
    """
    Records an operational enumeration failure for a persistence category.

    Safety Rule:
    - If the category was already ACCEPTED_TRUSTED, the accepted baseline is NEVER destroyed.
      The state remains ACCEPTED_TRUSTED, and last_enumeration_status is set to FAILED so diffing
      can be safely skipped for this cycle.
    - If the category was NOT_INITIALIZED, baseline_state transitions to ENUMERATION_FAILED.
    """
    if category not in VALID_CATEGORIES:
        raise ValueError(f"Invalid category '{category}', must be one of {VALID_CATEGORIES}")
    if not isinstance(error_message, str) or not error_message.strip():
        raise ValueError("error_message must be a non-empty string")

    with get_connection(db_path) as conn:
        meta = conn.execute(
            "SELECT baseline_state FROM persistence_baseline_meta WHERE category = ?;",
            (category,),
        ).fetchone()

        if not meta:
            raise ValueError(f"Category metadata row for '{category}' does not exist")

        if meta["baseline_state"] == "ACCEPTED_TRUSTED":
            # Preserve accepted baseline! Only record operational failure
            conn.execute(
                """
                UPDATE persistence_baseline_meta
                SET last_enumeration_status = 'FAILED',
                    last_error = ?
                WHERE category = ?;
                """,
                (error_message.strip(), category),
            )
            logger.warning(
                "Enumeration failure in ACCEPTED_TRUSTED category '%s'; accepted reference preserved: %s",
                category,
                error_message,
            )
        elif meta["baseline_state"] == "CANDIDATE_REVIEW":
            # Preserve candidate review state and record failure
            conn.execute(
                """
                UPDATE persistence_baseline_meta
                SET last_enumeration_status = 'FAILED',
                    last_error = ?
                WHERE category = ?;
                """,
                (error_message.strip(), category),
            )
        else:
            # Uninitialized category
            conn.execute(
                """
                UPDATE persistence_baseline_meta
                SET baseline_state = 'ENUMERATION_FAILED',
                    last_enumeration_status = 'FAILED',
                    last_error = ?
                WHERE category = ?;
                """,
                (error_message.strip(), category),
            )


def reset_all_baselines_atomic(db_path: Optional[str] = None) -> None:
    """
    Atomically clears all baseline records (both candidate and accepted) and resets
    metadata to NOT_INITIALIZED inside an isolated database transaction.
    Requires a complete new candidate capture and acceptance cycle before diffing resumes.
    """
    with get_connection(db_path) as conn:
        conn.execute("DELETE FROM persistence_baseline;")
        conn.execute(
            """
            UPDATE persistence_baseline_meta
            SET baseline_state = 'NOT_INITIALIZED',
                candidate_captured_at = NULL,
                accepted_at = NULL,
                last_reset_at = CURRENT_TIMESTAMP,
                candidate_entry_count = 0,
                accepted_entry_count = 0,
                last_enumeration_status = 'PENDING',
                last_error = NULL;
            """
        )
        logger.info("All persistence baselines atomically reset to NOT_INITIALIZED")


# ---------------------------------------------------------------------------
# Baseline Dictionary with Category Identity Preservation
# ---------------------------------------------------------------------------
class BaselineDict(dict):
    """
    Dictionary of baseline entries preserving category identity across all sources.
    Primary keys are composite tuples (entry_type, entry_key).

    Features & Ergonomics:
    - Eliminates cross-category key collisions when querying across categories (category=None).
    - Composite tuple lookup: d[(entry_type, entry_key)]
    - Scoped single-key lookup: d[entry_key] when scoped to a specific category.
    - Unscoped unambiguous single-key lookup: d[entry_key] when the key is unique across categories.
    - Conflict rejection: d[entry_key] raises KeyError with descriptive error if entry_key exists in multiple categories.
    - Membership testing: (entry_type, entry_key) in d or entry_key in d.
    - Grouping helper: d.by_category() returns Dict[str, Dict[str, Dict[str, Any]]] ({category: {entry_key: entry_dict}}).
    """

    def __init__(self, *args, scoped_category: Optional[str] = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.scoped_category = scoped_category

    def __getitem__(self, key: Any) -> Any:
        if isinstance(key, tuple) and len(key) == 2:
            return super().__getitem__(key)
        if isinstance(key, str):
            if self.scoped_category is not None:
                tuple_key = (self.scoped_category, key)
                if tuple_key in self:
                    return super().__getitem__(tuple_key)
                raise KeyError(f"Entry key '{key}' not found in category '{self.scoped_category}'")
            # Unscoped query (all categories)
            matches = [v for (cat, k), v in self.items() if k == key]
            if len(matches) == 1:
                return matches[0]
            elif len(matches) > 1:
                matching_cats = [cat for (cat, k) in self.keys() if k == key]
                raise KeyError(
                    f"Ambiguous entry_key '{key}' appears in multiple categories: {matching_cats}. "
                    f"Access via composite key (category, entry_key) or use .by_category()"
                )
            raise KeyError(f"Entry key '{key}' not found in baseline")
        return super().__getitem__(key)

    def __contains__(self, key: Any) -> bool:
        if isinstance(key, tuple) and len(key) == 2:
            return super().__contains__(key)
        if isinstance(key, str):
            if self.scoped_category is not None:
                return super().__contains__((self.scoped_category, key))
            return any(k == key for (_, k) in self.keys())
        return super().__contains__(key)

    def get(self, key: Any, default: Any = None) -> Any:
        try:
            return self[key]
        except KeyError:
            return default

    def by_category(self) -> Dict[str, Dict[str, Dict[str, Any]]]:
        """Returns baseline entries grouped by category: {category: {entry_key: entry_dict}}."""
        grouped: Dict[str, Dict[str, Dict[str, Any]]] = {}
        for (cat, k), v in self.items():
            grouped.setdefault(cat, {})[k] = v
        return grouped


def get_persistence_baseline(
    category: Optional[str] = None,
    only_accepted: bool = True,
    db_path: Optional[str] = None,
) -> BaselineDict:
    """
    Retrieves baseline entries preserving category identity.
    Returns a BaselineDict keyed by composite tuple (entry_type, entry_key).
    Supports single-key lookup when scoped to a category or when unambiguous,
    and provides .by_category() grouping helper.
    When only_accepted=True, only retrieves entries where is_candidate = 0.
    """
    if category is not None and category not in VALID_CATEGORIES:
        raise ValueError(f"Invalid category '{category}', must be one of {VALID_CATEGORIES}")

    query = "SELECT * FROM persistence_baseline WHERE 1=1"
    params: List[Any] = []

    if only_accepted:
        query += " AND is_candidate = 0"

    if category:
        query += " AND entry_type = ?"
        params.append(category)

    with get_connection(db_path) as conn:
        rows = conn.execute(query, params).fetchall()
        result = BaselineDict(scoped_category=category)
        for r in rows:
            result[(r["entry_type"], r["entry_key"])] = dict(r)
        return result


def get_candidate_baseline(
    category: Optional[str] = None,
    db_path: Optional[str] = None,
) -> BaselineDict:
    """
    Retrieves candidate baseline entries awaiting operator review (is_candidate = 1).
    Returns a BaselineDict keyed by composite tuple (entry_type, entry_key).
    Supports single-key lookup when scoped to a category or when unambiguous,
    and provides .by_category() grouping helper.
    """
    if category is not None and category not in VALID_CATEGORIES:
        raise ValueError(f"Invalid category '{category}', must be one of {VALID_CATEGORIES}")

    query = "SELECT * FROM persistence_baseline WHERE is_candidate = 1"
    params: List[Any] = []

    if category:
        query += " AND entry_type = ?"
        params.append(category)

    with get_connection(db_path) as conn:
        rows = conn.execute(query, params).fetchall()
        result = BaselineDict(scoped_category=category)
        for r in rows:
            result[(r["entry_type"], r["entry_key"])] = dict(r)
        return result


def compute_baseline_diff(
    category: Optional[str] = None,
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Computes forensic baseline diff comparing accepted reference baseline (is_candidate = 0)
    with candidate inventory (is_candidate = 1).
    Categorizes entries into:
      - ADDED: Entries present in candidate inventory but absent from accepted baseline.
      - REMOVED: Entries present in accepted baseline but absent from candidate inventory.
      - MODIFIED: Entries present in both with fingerprint or value changes.
      - UNCHANGED: Entries identical in key, value, and fingerprint.
    """
    effective_db = db_path or config.DB_PATH
    if category is not None and category not in VALID_CATEGORIES:
        raise ValueError(f"Invalid category '{category}', must be one of {VALID_CATEGORIES}")

    categories = [category] if category else list(VALID_CATEGORIES)
    all_meta = get_all_baseline_meta(db_path=effective_db)

    diff_results = {}
    for cat in categories:
        meta = all_meta.get(cat, {})
        state = meta.get("baseline_state", "NOT_INITIALIZED")

        candidates = get_candidate_baseline(category=cat, db_path=effective_db)
        accepted = get_persistence_baseline(category=cat, only_accepted=True, db_path=effective_db)

        cand_map = {k[1]: v for k, v in candidates.items()}
        acc_map = {k[1]: v for k, v in accepted.items()}

        added: List[Dict[str, Any]] = []
        removed: List[Dict[str, Any]] = []
        modified: List[Dict[str, Any]] = []
        unchanged: List[Dict[str, Any]] = []

        for key, cand in cand_map.items():
            if key not in acc_map:
                added.append({
                    "entry_type": cat,
                    "entry_key": key,
                    "entry_value": cand.get("entry_value", ""),
                    "fingerprint": cand.get("fingerprint", ""),
                    "captured_at": cand.get("captured_at"),
                })
            else:
                acc = acc_map[key]
                val_changed = cand.get("entry_value") != acc.get("entry_value")
                fp_changed = cand.get("fingerprint") != acc.get("fingerprint")
                if val_changed or fp_changed:
                    modified.append({
                        "entry_type": cat,
                        "entry_key": key,
                        "old_value": acc.get("entry_value", ""),
                        "new_value": cand.get("entry_value", ""),
                        "old_fingerprint": acc.get("fingerprint", ""),
                        "new_fingerprint": cand.get("fingerprint", ""),
                        "captured_at": cand.get("captured_at"),
                    })
                else:
                    unchanged.append({
                        "entry_type": cat,
                        "entry_key": key,
                        "entry_value": cand.get("entry_value", ""),
                        "fingerprint": cand.get("fingerprint", ""),
                    })

        for key, acc in acc_map.items():
            if key not in cand_map:
                removed.append({
                    "entry_type": cat,
                    "entry_key": key,
                    "entry_value": acc.get("entry_value", ""),
                    "fingerprint": acc.get("fingerprint", ""),
                    "accepted_at": acc.get("accepted_at"),
                })

        diff_results[cat] = {
            "category": cat,
            "state": state,
            "counts": {
                "added": len(added),
                "removed": len(removed),
                "modified": len(modified),
                "unchanged": len(unchanged),
                "candidate_total": len(cand_map),
                "accepted_total": len(acc_map),
            },
            "added": added,
            "removed": removed,
            "modified": modified,
            "unchanged": unchanged,
        }

    if category:
        return diff_results.get(category, {})
    return diff_results
