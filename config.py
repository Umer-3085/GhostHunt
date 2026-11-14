SCAN_INTERVAL_SECONDS = 10
DB_PATH = "ghosthunt.db"
STARTUP_REGISTRY_PATHS = [
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
]
RISK_WEIGHTS = {
    "process_view": 0.4,
    "persistence": 0.3,
    "signature": 0.3,
}
HIGH_RISK_THRESHOLD = 0.6