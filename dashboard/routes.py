"""
GhostHunt — Phase 6: Web Dashboard & REST API Routes
Authoritative route handlers and REST endpoints specified in DEVELOPMENT_ROADMAP.md (Version 1.4.3).

Architectural Invariants & Safeguards:
1. No business logic in routes: delegates to core DAL, correlator, and scheduler.
2. In-process concurrency guard: manual scan, baseline accept, and reset use GLOBAL_SCHEDULER lock.
   Concurrent requests return HTTP 409 Conflict.
3. Strict separation of threat findings and operational diagnostics.
4. Input validation: strict integer validation, parameter whitelisting, and no raw SQL fragments.
5. CSRF protection on state-changing browser requests.
6. Safe error responses: stack traces and sensitive config are never exposed.
"""

import json
import logging
from typing import Any, Dict, List, Optional, Tuple

from flask import (
    Blueprint,
    abort,
    current_app,
    jsonify,
    render_template,
    request,
    session,
)

import config
import core.db as db
import core.scheduler as scheduler

logger = logging.getLogger("ghosthunt.dashboard.routes")

dashboard_bp = Blueprint("dashboard", __name__)


def get_active_db_path() -> str:
    """Returns the effective database path from current Flask app configuration."""
    return current_app.config.get("DB_PATH", config.DB_PATH)


def validate_csrf() -> None:
    """
    Validates CSRF token for state-changing browser requests.
    Enforces token validation whenever a browser session cookie is attached.
    Exempts purely programmatic API clients without session cookies.
    """
    if not current_app.config.get("CSRF_ENABLED", True):
        return

    if request.method in ("POST", "PUT", "DELETE", "PATCH"):
        session_cookie_name = current_app.config.get("SESSION_COOKIE_NAME", "session")
        has_session_cookie = session_cookie_name in request.cookies

        # If request carries a browser session cookie, enforce CSRF validation
        if has_session_cookie:
            expected_token = session.get("csrf_token")
            provided_token = (
                request.headers.get("X-CSRF-Token")
                or request.form.get("csrf_token")
                or (request.get_json(silent=True) or {}).get("csrf_token")
            )

            import secrets
            if not expected_token or not provided_token or not secrets.compare_digest(str(provided_token), str(expected_token)):
                logger.warning("CSRF validation failed for %s from %s", request.path, request.remote_addr)
                abort(400, description="CSRF token missing or invalid")


@dashboard_bp.before_request
def check_csrf_protection() -> None:
    """Enforces CSRF protection on incoming state-changing requests."""
    validate_csrf()


# ===========================================================================
# 1. REST API: Health & System Status (FR-6.6)
# ===========================================================================
@dashboard_bp.route("/api/health", methods=["GET"])
@dashboard_bp.route("/api/status", methods=["GET"])
def api_status():
    """
    Returns application health, database connectivity, and scheduler status.
    Never reports healthy if database connectivity is broken.
    """
    db_path = get_active_db_path()
    db_connected = False
    latest_scan_id = None
    latest_scan = None

    try:
        latest_scan_id = db.get_latest_completed_scan_id(db_path=db_path)
        if latest_scan_id is not None:
            latest_scan = db.get_scan_status(latest_scan_id, db_path=db_path)
        db_connected = True
    except Exception as ex:
        logger.error("Health check database probe failed: %s", ex)
        return jsonify({
            "success": False,
            "status": "error",
            "db_connected": False,
            "message": "Database connectivity failure",
            "version": config.APP_VERSION,
        }), 503

    sched = scheduler.GLOBAL_SCHEDULER
    scan_progress = scheduler.get_scan_progress()

    return jsonify({
        "success": True,
        "status": "ok",
        "app_name": config.APP_NAME,
        "version": config.APP_VERSION,
        "environment": config.GHOSTHUNT_ENV,
        "db_connected": db_connected,
        "scheduler": {
            "is_running": sched.is_running,
            "scan_count": sched.scan_count,
            "error_count": sched.error_count,
            "last_scan_time": sched.last_scan_time,
            "interval_seconds": sched.interval_seconds,
        },
        "latest_completed_scan_id": latest_scan_id,
        "latest_scan": latest_scan,
        "scan_progress": scan_progress,
    }), 200


# ===========================================================================
# 2. REST API: Scan Management (FR-5.2, FR-6.6)
# ===========================================================================
@dashboard_bp.route("/api/scan", methods=["POST"])
def api_trigger_scan():
    """
    Triggers an immediate scan cycle guarded by the shared operation lock.
    Returns HTTP 409 Conflict if another scan or reset is active.
    Supports asynchronous execution via ?async=true or JSON {"async": true}.
    """
    db_path = get_active_db_path()
    sched = scheduler.GLOBAL_SCHEDULER
    # Temporarily set scheduler db_path to match active app config
    sched.db_path = db_path

    payload = request.get_json(silent=True) or {}
    is_async = (
        request.args.get("async", "").lower() in ("1", "true")
        or payload.get("async") is True
        or request.headers.get("X-Async-Scan", "").lower() in ("1", "true")
    )

    if is_async:
        res = sched.trigger_manual_scan_async()
        if res.get("status") == "busy":
            return jsonify({
                "success": False,
                "status": "busy",
                "error": "Conflict",
                "message": res.get("message", "Another protected operation is in progress."),
            }), 409
        return jsonify(res), 202

    res = sched.trigger_manual_scan(timeout=0.0)

    if res.get("status") == "busy":
        return jsonify({
            "success": False,
            "status": "busy",
            "error": "Conflict",
            "message": res.get("message", "Another protected operation is in progress."),
        }), 409

    if not res.get("success"):
        return jsonify({
            "success": False,
            "status": "failed",
            "error": "Scan Failed",
            "message": res.get("message", "Scan execution failed"),
        }), 500

    return jsonify({
        "success": True,
        "status": "completed",
        "scan_id": res.get("scan_id"),
        "total_findings": res.get("total_findings", 0),
        "high_risk_count": res.get("high_risk_count", 0),
        "duration_ms": res.get("duration_ms", 0.0),
    }), 200


@dashboard_bp.route("/api/scan/latest", methods=["GET"])
def api_latest_scan():
    """Returns the details of the latest completed scan."""
    db_path = get_active_db_path()
    latest_id = db.get_latest_completed_scan_id(db_path=db_path)
    if latest_id is None:
        return jsonify({
            "success": False,
            "message": "No completed scans exist yet",
        }), 404

    status = db.get_scan_status(latest_id, db_path=db_path)
    return jsonify({"success": True, "scan": status}), 200


@dashboard_bp.route("/api/scan/progress", methods=["GET"])
@dashboard_bp.route("/api/scan/<int:scan_id>/progress", methods=["GET"])
def api_scan_progress(scan_id: Optional[int] = None):
    """
    Returns the current in-progress scan phase and progress percentage.
    If scan_id is provided, returns progress or completed status for that specific scan.
    Used by the UI to display a live progress panel during active scans.
    """
    progress = scheduler.get_scan_progress()
    if scan_id is not None:
        if progress.get("scan_id") == scan_id:
            return jsonify({
                "success": True,
                "scan_id": scan_id,
                "progress": progress,
            }), 200

        db_path = get_active_db_path()
        status = db.get_scan_status(scan_id, db_path=db_path)
        if status is not None:
            is_done = status.get("status") == "COMPLETED"
            return jsonify({
                "success": True,
                "scan_id": scan_id,
                "progress": {
                    "scan_id": scan_id,
                    "phase": "complete" if is_done else status.get("status", "unknown").lower(),
                    "progress": 100 if is_done else 0,
                },
                "scan": status,
            }), 200

    return jsonify({
        "success": True,
        "progress": progress,
    }), 200


@dashboard_bp.route("/api/scan/<int:scan_id>", methods=["GET"])
def api_get_scan(scan_id: int):
    """Retrieves status and metadata for a specific scan_id."""
    if scan_id <= 0:
        abort(400, description="scan_id must be a positive integer")

    db_path = get_active_db_path()
    status = db.get_scan_status(scan_id, db_path=db_path)
    if status is None:
        return jsonify({
            "success": False,
            "message": f"Scan with ID {scan_id} not found",
        }), 404

    return jsonify({"success": True, "scan": status}), 200


# ===========================================================================
# 3. REST API: Risk-Ranked Entities (FR-4, FR-6.6)
# ===========================================================================
@dashboard_bp.route("/api/scores", methods=["GET"])
def api_scores():
    """
    Retrieves correlated risk-ranked entities for a scan (default: latest completed scan).
    Supports pagination (page, per_page) and filtering (severity, signal).
    Preserves exact database risk scores and severities.
    """
    db_path = get_active_db_path()

    # 1. Validate pagination parameters early
    try:
        page = int(request.args.get("page", 1))
        per_page = int(request.args.get("per_page", 50))
        if page < 1:
            raise ValueError()
        if per_page < 1 or per_page > 500:
            raise ValueError()
    except ValueError:
        abort(400, description="Invalid page or per_page parameters (page >= 1, 1 <= per_page <= 500)")

    # 2. Resolve scan_id
    raw_scan_id = request.args.get("scan_id")
    if raw_scan_id is not None:
        try:
            scan_id = int(raw_scan_id)
            if scan_id <= 0:
                raise ValueError()
        except ValueError:
            abort(400, description="Invalid scan_id parameter")
    else:
        scan_id = db.get_latest_completed_scan_id(db_path=db_path)

    if scan_id is None:
        return jsonify({
            "success": True,
            "scan_id": None,
            "total_count": 0,
            "page": page,
            "per_page": per_page,
            "total_pages": 0,
            "entities": [],
        }), 200

    # 3. Fetch risk scores from DAL
    all_scores = db.get_risk_scores_for_scan(scan_id, db_path=db_path)

    # 4. Optional filtering
    severity_filter = request.args.get("severity")
    if severity_filter:
        sev_upper = severity_filter.upper().strip()
        if sev_upper not in ("LOW", "MEDIUM", "HIGH"):
            abort(400, description="Invalid severity filter (must be LOW, MEDIUM, or HIGH)")
        all_scores = [r for r in all_scores if r.get("risk_level") == sev_upper]

    signal_filter = request.args.get("signal")
    if signal_filter:
        sig_clean = signal_filter.lower().strip()
        all_scores = [
            r for r in all_scores
            if sig_clean in r.get("signals_triggered", "").split(",")
        ]

    # 5. Paginate results
    total_count = len(all_scores)
    total_pages = (total_count + per_page - 1) // per_page if total_count > 0 else 0
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    paged_entities = all_scores[start_idx:end_idx]

    # 6. Delta calculation if since_scan_id is provided
    delta = None
    raw_since = request.args.get("since_scan_id")
    if raw_since is not None:
        try:
            since_id = int(raw_since)
            if since_id > 0 and since_id != scan_id:
                prev_scores = db.get_risk_scores_for_scan(since_id, db_path=db_path)
                prev_map = {p.get("item_key") or f"{p.get('process_name')}:{p.get('pid')}": p for p in prev_scores}
                curr_map = {c.get("item_key") or f"{c.get('process_name')}:{c.get('pid')}": c for c in all_scores}

                new_rows = [c for k, c in curr_map.items() if k not in prev_map]
                updated_rows = []
                for k, c in curr_map.items():
                    if k in prev_map:
                        p = prev_map[k]
                        if p.get("risk_level") != c.get("risk_level") or abs(p.get("score", 0) - c.get("score", 0)) > 0.01:
                            c_copy = dict(c)
                            c_copy["prev_risk_level"] = p.get("risk_level")
                            c_copy["prev_score"] = p.get("score")
                            updated_rows.append(c_copy)
                delta = {
                    "new_entities": new_rows,
                    "updated_entities": updated_rows,
                    "new_count": len(new_rows),
                    "updated_count": len(updated_rows),
                }
        except ValueError:
            pass

    response_data = {
        "success": True,
        "scan_id": scan_id,
        "total_count": total_count,
        "page": page,
        "per_page": per_page,
        "total_pages": total_pages,
        "entities": paged_entities,
    }
    if delta is not None:
        response_data["delta"] = delta

    return jsonify(response_data), 200


# ===========================================================================
# 4. REST API: Forensic Evidence & Findings (FR-4.6, FR-6.3)
# ===========================================================================
@dashboard_bp.route("/api/findings/<int:scan_id>", methods=["GET"])
def api_findings(scan_id: int):
    """
    Retrieves forensic findings for a scan with optional filters.
    Preserves finding_type and score_eligibility.
    """
    if scan_id <= 0:
        abort(400, description="scan_id must be a positive integer")

    db_path = get_active_db_path()
    findings = db.get_findings_for_scan(scan_id, include_diagnostics=True, db_path=db_path)

    # Optional filtering
    ft_filter = request.args.get("finding_type")
    if ft_filter:
        ft_clean = ft_filter.lower().strip()
        if ft_clean not in ("threat", "diagnostic"):
            abort(400, description="finding_type filter must be 'threat' or 'diagnostic'")
        findings = [f for f in findings if f.get("finding_type") == ft_clean]

    sig_filter = request.args.get("signal")
    if sig_filter:
        sig_clean = sig_filter.lower().strip()
        findings = [f for f in findings if f.get("signal") == sig_clean]

    return jsonify({
        "success": True,
        "scan_id": scan_id,
        "total_count": len(findings),
        "findings": findings,
    }), 200


@dashboard_bp.route("/api/process/<int:pid>/findings", methods=["GET"])
def api_process_findings(pid: int):
    """
    Retrieves forensic findings for a specific PID, clearly distinguishing
    threat findings from operational diagnostics.
    """
    if pid < 0:
        abort(400, description="pid must be a non-negative integer")

    db_path = get_active_db_path()
    raw_scan_id = request.args.get("scan_id")
    if raw_scan_id is not None:
        try:
            scan_id = int(raw_scan_id)
            if scan_id <= 0:
                raise ValueError()
        except ValueError:
            abort(400, description="Invalid scan_id parameter")
    else:
        scan_id = db.get_latest_completed_scan_id(db_path=db_path)

    if scan_id is None:
        return jsonify({
            "success": True,
            "scan_id": None,
            "pid": pid,
            "threats": [],
            "diagnostics": [],
        }), 200

    findings = db.get_findings_for_process(scan_id, pid, include_diagnostics=True, db_path=db_path)

    threats = [f for f in findings if f.get("finding_type") == "threat"]
    diagnostics = [f for f in findings if f.get("finding_type") == "diagnostic"]

    return jsonify({
        "success": True,
        "scan_id": scan_id,
        "pid": pid,
        "total_findings": len(findings),
        "threats": threats,
        "diagnostics": diagnostics,
    }), 200


# ===========================================================================
# 5. REST API: Historical Scan Log (FR-6.5)
# ===========================================================================
@dashboard_bp.route("/api/history", methods=["GET"])
def api_history():
    """Retrieves immutable historical scan execution logs."""
    db_path = get_active_db_path()
    try:
        limit = int(request.args.get("limit", 50))
        if limit < 1 or limit > 500:
            raise ValueError()
    except ValueError:
        abort(400, description="Invalid limit parameter (1 <= limit <= 500)")

    history = db.get_scan_history(limit=limit, db_path=db_path)
    return jsonify({
        "success": True,
        "count": len(history),
        "history": history,
    }), 200


@dashboard_bp.route("/api/scans/recent", methods=["GET"])
def api_recent_scans():
    """
    Returns the last 10 completed scans with summary data for the timeline card.
    """
    db_path = get_active_db_path()
    completed = db.get_recent_completed_scans(limit=10, db_path=db_path)
    return jsonify({
        "success": True,
        "count": len(completed),
        "scans": completed,
    }), 200


# ===========================================================================
# 6. REST API: Persistence Baseline Management (FR-2, FR-6.6)
# ===========================================================================
@dashboard_bp.route("/api/baseline", methods=["GET"])
def api_baseline_meta():
    """Returns baseline metadata states across registry, tasks, and services."""
    db_path = get_active_db_path()
    meta = db.get_all_baseline_meta(db_path=db_path)
    for cat_data in meta.values():
        cat_data["state"] = cat_data.get("baseline_state", "NOT_INITIALIZED")
    return jsonify({"success": True, "categories": meta}), 200


@dashboard_bp.route("/api/baseline/candidates", methods=["GET"])
def api_baseline_candidates():
    """Returns candidate baseline entries awaiting operator review."""
    db_path = get_active_db_path()
    category = request.args.get("category")
    if category and category not in config.PERSISTENCE_CATEGORIES:
        abort(400, description=f"Invalid category: must be one of {config.PERSISTENCE_CATEGORIES}")

    candidates = db.get_candidate_baseline(category=category, db_path=db_path)
    return jsonify({
        "success": True,
        "count": len(candidates),
        "candidates": [dict(entry) for entry in candidates.values()],
    }), 200


@dashboard_bp.route("/api/baseline/accepted", methods=["GET"])
def api_baseline_accepted():
    """Returns accepted reference baseline entries."""
    db_path = get_active_db_path()
    category = request.args.get("category")
    if category and category not in config.PERSISTENCE_CATEGORIES:
        abort(400, description=f"Invalid category: must be one of {config.PERSISTENCE_CATEGORIES}")

    accepted = db.get_persistence_baseline(category=category, only_accepted=True, db_path=db_path)
    return jsonify({
        "success": True,
        "count": len(accepted),
        "accepted": [dict(entry) for entry in accepted.values()],
    }), 200


@dashboard_bp.route("/api/baseline/diff", methods=["GET"])
def api_baseline_diff():
    """
    Returns structured forensic diff comparing accepted baseline vs candidate inventory.
    Categorizes entries into ADDED, REMOVED, MODIFIED, and UNCHANGED.
    """
    db_path = get_active_db_path()
    category = request.args.get("category")
    if category and category not in config.PERSISTENCE_CATEGORIES:
        abort(400, description=f"Invalid category: must be one of {config.PERSISTENCE_CATEGORIES}")

    diff_data = db.compute_baseline_diff(category=category, db_path=db_path)
    return jsonify({"success": True, "diff": diff_data}), 200


@dashboard_bp.route("/api/baseline/accept", methods=["POST"])
def api_baseline_accept():
    """
    Explicitly accepts candidate baselines, transitioning category to ACCEPTED_TRUSTED.
    Guarded by the shared operation lock. Returns HTTP 409 Conflict if busy.
    """
    db_path = get_active_db_path()
    sched = scheduler.GLOBAL_SCHEDULER

    payload = request.get_json(silent=True) or {}
    category = payload.get("category") or request.form.get("category")
    if category and category not in config.PERSISTENCE_CATEGORIES:
        abort(400, description=f"Invalid category: must be one of {config.PERSISTENCE_CATEGORIES}")

    # Guarded by shared lock
    lock_res = sched.execute_with_lock(
        db.accept_baseline_atomic,
        category=category,
        db_path=db_path,
        timeout=0.0,
    )

    if lock_res.get("status") == "busy":
        return jsonify({
            "success": False,
            "status": "busy",
            "error": "Conflict",
            "message": "Another protected operation is currently in progress.",
        }), 409

    if not lock_res.get("success"):
        err_msg = lock_res.get("message", "Baseline acceptance failed")
        return jsonify({
            "success": False,
            "status": "failed",
            "error": "Bad Request",
            "message": err_msg,
        }), 400

    return jsonify({
        "success": True,
        "status": "accepted",
        "result": lock_res.get("result"),
    }), 200


@dashboard_bp.route("/api/baseline/reset", methods=["POST"])
def api_baseline_reset():
    """
    Resets persistence baseline to NOT_INITIALIZED and wipes baseline records.
    Guarded by the shared operation lock. Requires explicit confirmation flag.
    Returns HTTP 409 Conflict if busy.
    """
    db_path = get_active_db_path()
    sched = scheduler.GLOBAL_SCHEDULER

    payload = request.get_json(silent=True) or {}
    confirm = payload.get("confirm") or request.form.get("confirm")
    if confirm not in (True, "true", "1", 1):
        abort(400, description="Reset confirmation required: must pass {'confirm': true}")

    lock_res = sched.execute_with_lock(
        db.reset_all_baselines_atomic,
        db_path=db_path,
        timeout=0.0,
    )

    if lock_res.get("status") == "busy":
        return jsonify({
            "success": False,
            "status": "busy",
            "error": "Conflict",
            "message": "Another protected operation is currently in progress.",
        }), 409

    if not lock_res.get("success"):
        return jsonify({
            "success": False,
            "status": "failed",
            "message": lock_res.get("message", "Baseline reset failed"),
        }), 500

    return jsonify({
        "success": True,
        "status": "reset",
        "message": "All persistence baselines successfully reset to NOT_INITIALIZED",
    }), 200


# ===========================================================================
# 7. Dashboard HTML Page Views (FR-6.1 - FR-6.5)
# ===========================================================================
@dashboard_bp.route("/", methods=["GET"])
def view_index():
    """
    Main Overview Dashboard:
    Renders summary metric cards, risk-ranked entity table, and the
    Candidate Baseline Review & Acceptance panel when categories require review.
    """
    db_path = get_active_db_path()
    latest_scan_id = db.get_latest_completed_scan_id(db_path=db_path)

    scan_info = None
    entities = []
    high_count = 0
    med_count = 0
    low_count = 0
    threat_findings_count = 0
    diag_findings_count = 0

    if latest_scan_id is not None:
        scan_info = db.get_scan_status(latest_scan_id, db_path=db_path)
        entities = db.get_risk_scores_for_scan(latest_scan_id, db_path=db_path)
        high_count = sum(1 for e in entities if e.get("risk_level") == "HIGH")
        med_count = sum(1 for e in entities if e.get("risk_level") == "MEDIUM")
        low_count = sum(1 for e in entities if e.get("risk_level") == "LOW")

        all_findings = db.get_findings_for_scan(latest_scan_id, include_diagnostics=True, db_path=db_path)
        threat_findings_count = sum(1 for f in all_findings if f.get("finding_type") == "threat")
        diag_findings_count = sum(1 for f in all_findings if f.get("finding_type") == "diagnostic")

    # Baseline metadata for review panel
    baseline_meta = db.get_all_baseline_meta(db_path=db_path)
    for cat_data in baseline_meta.values():
        cat_data["state"] = cat_data.get("baseline_state", "NOT_INITIALIZED")
    has_candidate_review = any(
        m.get("state") == "CANDIDATE_REVIEW" or m.get("baseline_state") == "CANDIDATE_REVIEW"
        for m in baseline_meta.values()
    )

    return render_template(
        "index.html",
        latest_scan_id=latest_scan_id,
        scan=scan_info,
        entities=entities,
        high_count=high_count,
        med_count=med_count,
        low_count=low_count,
        threat_count=threat_findings_count,
        diag_count=diag_findings_count,
        baseline_meta=baseline_meta,
        has_candidate_review=has_candidate_review,
        scheduler_running=scheduler.GLOBAL_SCHEDULER.is_running,
    )


@dashboard_bp.route("/process/<int:pid>", methods=["GET"])
def view_process_detail(pid: int):
    """
    Forensic Evidence View for a specific PID:
    Displays process identity cards, threat findings, and operational diagnostics separately.
    """
    db_path = get_active_db_path()
    raw_scan_id = request.args.get("scan_id")
    if raw_scan_id:
        try:
            scan_id = int(raw_scan_id)
        except ValueError:
            scan_id = db.get_latest_completed_scan_id(db_path=db_path)
    else:
        scan_id = db.get_latest_completed_scan_id(db_path=db_path)

    if scan_id is None:
        return render_template("process_detail.html", pid=pid, scan_id=None, entity=None, threats=[], diagnostics=[])

    findings = db.get_findings_for_process(scan_id, pid, include_diagnostics=True, db_path=db_path)
    threats = [f for f in findings if f.get("finding_type") == "threat"]
    diagnostics = [f for f in findings if f.get("finding_type") == "diagnostic"]

    # Retrieve correlated entity score
    all_scores = db.get_risk_scores_for_scan(scan_id, db_path=db_path)
    matching_entity = next((e for e in all_scores if e.get("pid") == pid), None)

    return render_template(
        "process_detail.html",
        pid=pid,
        scan_id=scan_id,
        entity=matching_entity,
        threats=threats,
        diagnostics=diagnostics,
    )


@dashboard_bp.route("/system-findings", methods=["GET"])
def view_system_findings():
    """
    System Findings View:
    Displays dormant persistence items (registry autoruns, tasks, services) where PID=None.
    """
    db_path = get_active_db_path()
    raw_scan_id = request.args.get("scan_id")
    if raw_scan_id:
        try:
            scan_id = int(raw_scan_id)
        except ValueError:
            scan_id = db.get_latest_completed_scan_id(db_path=db_path)
    else:
        scan_id = db.get_latest_completed_scan_id(db_path=db_path)

    system_findings = []
    if scan_id is not None:
        system_findings = db.get_system_findings(scan_id, include_diagnostics=True, db_path=db_path)

    threats = [f for f in system_findings if f.get("finding_type") == "threat"]
    diagnostics = [f for f in system_findings if f.get("finding_type") == "diagnostic"]

    return render_template(
        "process_detail.html",
        pid=None,
        is_system=True,
        scan_id=scan_id,
        threats=threats,
        diagnostics=diagnostics,
    )


@dashboard_bp.route("/history", methods=["GET"])
@dashboard_bp.route("/history/<int:scan_id>", methods=["GET"])
def view_history(scan_id: Optional[int] = None):
    """
    Historical Scan Log View:
    Displays historical scans timeline with snapshot drill-down into any completed or failed scan.
    """
    db_path = get_active_db_path()
    history = db.get_scan_history(limit=50, db_path=db_path)

    selected_scan = None
    selected_entities = []
    selected_findings = []

    if scan_id is not None:
        selected_scan = db.get_scan_status(scan_id, db_path=db_path)
        if selected_scan:
            selected_entities = db.get_risk_scores_for_scan(scan_id, db_path=db_path)
            selected_findings = db.get_findings_for_scan(scan_id, include_diagnostics=True, db_path=db_path)

    return render_template(
        "history.html",
        history=history,
        selected_scan=selected_scan,
        selected_entities=selected_entities,
        selected_findings=selected_findings,
    )


@dashboard_bp.route("/baseline", methods=["GET"])
def view_baseline():
    """
    Baseline Review & Management View:
    Displays categories, candidate entries, accepted reference entries, and reset controls.
    """
    db_path = get_active_db_path()
    meta = db.get_all_baseline_meta(db_path=db_path)
    candidates = db.get_candidate_baseline(db_path=db_path)
    accepted = db.get_persistence_baseline(only_accepted=True, db_path=db_path)

    return render_template(
        "index.html",
        view_baseline_tab=True,
        baseline_meta=meta,
        candidates=[dict(c) for c in candidates.values()],
        accepted=[dict(a) for a in accepted.values()],
        scheduler_running=scheduler.GLOBAL_SCHEDULER.is_running,
    )


# ---------------------------------------------------------------------------
# Simulation & Validation Routes (Phase 7)
# ---------------------------------------------------------------------------

@dashboard_bp.route("/simulations", methods=["GET"])
def view_simulations():
    """
    Simulation & Validation View:
    Displays catalog of registered academic simulations with interactive triggers.
    """
    import simulators
    scenarios = simulators.list_scenarios()
    return render_template(
        "simulations.html",
        scenarios=scenarios,
        scheduler_running=scheduler.GLOBAL_SCHEDULER.is_running,
    )


@dashboard_bp.route("/api/scenarios", methods=["GET"])
def api_list_scenarios():
    """
    REST endpoint listing all registered simulation scenarios and descriptions.
    """
    import simulators
    scenarios = simulators.list_scenarios()
    return jsonify({
        "status": "ok",
        "count": len(scenarios),
        "scenarios": scenarios,
    }), 200


@dashboard_bp.route("/api/scenarios/run", methods=["POST"])
def api_run_scenarios():
    """
    REST endpoint executing one or all simulation scenarios safely against
    isolated temporary SQLite databases.
    """
    validate_csrf()
    import simulators.scenario_runner as runner

    payload = request.get_json(silent=True) or {}
    target_id = payload.get("scenario_id", "all")

    if target_id == "all":
        results = runner.run_all_scenarios()
        passed_count = sum(1 for r in results if r.get("passed"))
        return jsonify({
            "status": "ok",
            "total": len(results),
            "passed": passed_count,
            "failed": len(results) - passed_count,
            "results": results,
        }), 200
    else:
        res = runner.run_scenario(target_id)
        if not res or "error" in res and "not found in registry" in res.get("error", ""):
            return jsonify({"status": "error", "error": f"Scenario '{target_id}' not found"}), 404
        return jsonify({
            "status": "ok",
            "results": [res],
        }), 200

