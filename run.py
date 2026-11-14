"""
GhostHunt — Single-Process Application Launcher
Authoritative application entry point specified in DEVELOPMENT_ROADMAP.md (Version 1.4.3).

Architectural Constraints:
1. Runs a single Python process binding explicitly to localhost (127.0.0.1).
2. Explicitly disables Flask debug and reloader modes (debug=False, use_reloader=False).
3. Initializes the SQLite database foundation on startup.
4. Starts the background scan scheduler daemon thread.
5. Registers graceful shutdown handlers to terminate the scheduler thread cleanly.
"""

import atexit
import logging
import signal
import sys
from typing import Any

import config
import core.db as db
import core.scheduler as scheduler
from dashboard import create_app

logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL, logging.INFO),
    format=config.LOG_FORMAT,
)
logger = logging.getLogger("ghosthunt.launcher")


def main() -> None:
    logger.info("Starting %s v%s in %s mode...", config.APP_NAME, config.APP_VERSION, config.GHOSTHUNT_ENV)

    # 1. Initialize SQLite Database Foundation
    logger.info("Initializing SQLite database foundation at: %s", config.DB_PATH)
    db.init_db(config.DB_PATH)

    # 2. Start Background Scheduler Daemon Thread
    logger.info("Starting background scan scheduler daemon (interval: %.1fs)...", config.SCAN_INTERVAL_SECONDS)
    sched = scheduler.GLOBAL_SCHEDULER
    sched.db_path = config.DB_PATH
    sched.start()

    # 3. Clean Shutdown Handler
    def graceful_shutdown(*args: Any) -> None:
        logger.info("Initiating graceful shutdown...")
        sched.stop(timeout=3.0)
        logger.info("GhostHunt shutdown complete.")

    atexit.register(graceful_shutdown)

    # 4. Create Flask Application
    app = create_app()

    # 5. Launch Localhost Web Server (debug=False, use_reloader=False)
    logger.info(
        "GhostHunt Web Dashboard accessible at: http://%s:%d (localhost only)",
        config.FLASK_HOST, config.FLASK_PORT,
    )
    try:
        app.run(
            host=config.FLASK_HOST,
            port=config.FLASK_PORT,
            debug=False,
            use_reloader=False,
        )
    except (KeyboardInterrupt, SystemExit):
        graceful_shutdown()


if __name__ == "__main__":
    main()
