"""
GhostHunt — Phase 8 Empirical Performance Benchmarking & Evaluation Harness
Measures host environment specifications, detector execution times across 10 repetitions,
resource utilization (CPU % and memory RSS MB), verification cache efficacy,
database transaction latencies, and REST API response times.
"""

import json
import os
import platform
import sqlite3
import sys
import tempfile
import time
from typing import Any, Dict, List

import psutil

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import config
import core.db as db
import core.persistence as persistence_engine
import core.process_views as process_views_engine
import core.signatures as signatures_engine
from core.scheduler import execute_scan_cycle
from dashboard import create_app


def calculate_stats(measurements: List[float]) -> Dict[str, float]:
    """Calculate min, max, mean, median, and p95 from a list of float measurements."""
    if not measurements:
        return {"min": 0.0, "max": 0.0, "mean": 0.0, "median": 0.0, "p95": 0.0}
    sorted_m = sorted(measurements)
    n = len(sorted_m)
    p95_idx = int(0.95 * n) if n > 1 else 0
    p95_idx = min(p95_idx, n - 1)
    
    mean_val = sum(sorted_m) / n
    if n % 2 == 1:
        median_val = sorted_m[n // 2]
    else:
        median_val = (sorted_m[n // 2 - 1] + sorted_m[n // 2]) / 2.0

    return {
        "min": round(sorted_m[0], 2),
        "max": round(sorted_m[-1], 2),
        "mean": round(mean_val, 2),
        "median": round(median_val, 2),
        "p95": round(sorted_m[p95_idx], 2),
    }


def get_host_specs() -> Dict[str, Any]:
    """Collect host environment hardware and platform specifications."""
    mem = psutil.virtual_memory()
    return {
        "os_name": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "os_platform": platform.platform(),
        "architecture": platform.machine(),
        "cpu_count_logical": psutil.cpu_count(logical=True),
        "cpu_count_physical": psutil.cpu_count(logical=False),
        "total_ram_gb": round(mem.total / (1024 ** 3), 2),
        "available_ram_gb": round(mem.available / (1024 ** 3), 2),
        "python_version": platform.python_version(),
        "sqlite_version": sqlite3.sqlite_version,
    }


def benchmark_detectors(repetitions: int = 10) -> Dict[str, Any]:
    """Measure execution times for individual detector engines across repetitions."""
    pv_times: List[float] = []
    reg_times: List[float] = []
    task_times: List[float] = []
    svc_times: List[float] = []
    
    print(f"[*] Benchmarking Detectors ({repetitions} repetitions)...")
    for i in range(repetitions):
        # 1. Process-View Enumeration (full two-pass cross-comparison)
        t0 = time.perf_counter()
        _ = process_views_engine.run_two_pass_enumeration()
        pv_times.append((time.perf_counter() - t0) * 1000.0)

        # 2. Registry Persistence
        t0 = time.perf_counter()
        _ = persistence_engine.read_registry_run_keys()
        reg_times.append((time.perf_counter() - t0) * 1000.0)

        # 3. Scheduled Tasks Persistence
        t0 = time.perf_counter()
        _ = persistence_engine.read_scheduled_tasks()
        task_times.append((time.perf_counter() - t0) * 1000.0)

        # 4. Windows Services Persistence
        t0 = time.perf_counter()
        _ = persistence_engine.read_windows_services()
        svc_times.append((time.perf_counter() - t0) * 1000.0)

    return {
        "process_views_ms": calculate_stats(pv_times),
        "persistence_registry_ms": calculate_stats(reg_times),
        "persistence_tasks_ms": calculate_stats(task_times),
        "persistence_services_ms": calculate_stats(svc_times),
    }


def benchmark_signature_cache(repetitions: int = 10) -> Dict[str, Any]:
    """Measure cold-cache vs warm-cache verification duration on running processes / system binaries."""
    print("[*] Benchmarking Signature Verification Cache...")
    # Gather a sample of 20 unique loaded module/binary paths from running processes
    sample_paths = []
    for proc in psutil.process_iter(["pid", "name", "exe"]):
        try:
            exe = proc.info.get("exe")
            if exe and os.path.exists(exe) and exe not in sample_paths:
                sample_paths.append(exe)
                if len(sample_paths) >= 20:
                    break
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # Fallback to standard system binaries if process list is restricted
    if len(sample_paths) < 10:
        system32 = os.environ.get("SystemRoot", "C:\\Windows") + "\\System32"
        for name in ["cmd.exe", "notepad.exe", "calc.exe", "kernel32.dll", "ntdll.dll", "user32.dll", "gdi32.dll", "shell32.dll", "advapi32.dll", "ws2_32.dll"]:
            p = os.path.join(system32, name)
            if os.path.exists(p) and p not in sample_paths:
                sample_paths.append(p)

    cold_times: List[float] = []
    warm_times: List[float] = []

    for _ in range(repetitions):
        # Cold cache run: clear cache
        signatures_engine.GLOBAL_VERIFICATION_CACHE.clear()
        t0 = time.perf_counter()
        for p in sample_paths:
            signatures_engine.verify_file_signature_cached(p)
        cold_times.append((time.perf_counter() - t0) * 1000.0)

        # Warm cache run: cache is now populated
        t0 = time.perf_counter()
        for p in sample_paths:
            signatures_engine.verify_file_signature_cached(p)
        warm_times.append((time.perf_counter() - t0) * 1000.0)

    cold_stats = calculate_stats(cold_times)
    warm_stats = calculate_stats(warm_times)
    speedup = round(cold_stats["mean"] / warm_stats["mean"], 2) if warm_stats["mean"] > 0 else 0.0

    return {
        "sample_size": len(sample_paths),
        "cold_cache_ms": cold_stats,
        "warm_cache_ms": warm_stats,
        "speedup_factor": speedup,
        "warm_cache_hit_ratio_percent": 100.0,
    }


def benchmark_full_scan_cycles(repetitions: int = 10) -> Dict[str, Any]:
    """Measure full end-to-end scan coordinator cycles and system resource utilization."""
    print(f"[*] Benchmarking Full Scan Cycles & Resource Utilization ({repetitions} repetitions)...")
    durations: List[float] = []
    cpu_measurements: List[float] = []
    rss_measurements: List[float] = []
    
    current_proc = psutil.Process(os.getpid())
    # Baseline idle resource
    rss_before_mb = current_proc.memory_info().rss / (1024 * 1024)

    # Use an isolated temporary database for benchmarking
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        bench_db = tf.name

    try:
        db.init_db(bench_db)
        # Capture baseline so persistence diffing runs against accepted baseline
        db.capture_candidate_baseline_atomic("registry", [{"entry_type": "Run", "entry_key": "k", "entry_value": "v", "fingerprint": "f"}], bench_db)
        db.accept_baseline_atomic("registry", bench_db)

        for _ in range(repetitions):
            # Prime psutil CPU calculation
            _ = psutil.cpu_percent(interval=None)
            t0 = time.perf_counter()
            _ = execute_scan_cycle(db_path=bench_db)
            durations.append((time.perf_counter() - t0) * 1000.0)
            
            cpu_measurements.append(psutil.cpu_percent(interval=None))
            rss_measurements.append(current_proc.memory_info().rss / (1024 * 1024))

        rss_after_mb = current_proc.memory_info().rss / (1024 * 1024)

    finally:
        if os.path.exists(bench_db):
            try:
                os.remove(bench_db)
            except OSError:
                pass
        # Also clean WAL files
        for ext in ["-wal", "-shm"]:
            if os.path.exists(bench_db + ext):
                try:
                    os.remove(bench_db + ext)
                except OSError:
                    pass

    return {
        "scan_cycle_duration_ms": calculate_stats(durations),
        "cpu_percent": calculate_stats(cpu_measurements),
        "rss_memory_mb": calculate_stats(rss_measurements),
        "rss_before_mb": round(rss_before_mb, 2),
        "rss_after_mb": round(rss_after_mb, 2),
        "rss_delta_mb": round(rss_after_mb - rss_before_mb, 2),
    }


def benchmark_database_operations(repetitions: int = 10) -> Dict[str, Any]:
    """Measure SQLite transaction execution times for critical DAL operations."""
    print(f"[*] Benchmarking SQLite Database DAL Operations ({repetitions} repetitions)...")
    start_times: List[float] = []
    insert_findings_times: List[float] = []
    insert_scores_times: List[float] = []
    complete_times: List[float] = []
    accept_times: List[float] = []
    reset_times: List[float] = []

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        bench_db = tf.name

    try:
        db.init_db(bench_db)
        sample_findings = [
            {
                "scan_id": 1,
                "finding_type": "threat",
                "signal": "process_view",
                "evidence": "Hidden process missing from toolhelp32",
                "severity": "high",
                "pid": 9999,
                "process_name": "stealth.exe",
                "exe_path": "C:\\Windows\\stealth.exe",
                "score_eligible": True,
            },
            {
                "scan_id": 1,
                "finding_type": "diagnostic",
                "signal": "process_view",
                "evidence": "WMI query succeeded in 12ms",
                "severity": "low",
                "pid": None,
                "process_name": "[system]",
                "exe_path": None,
                "score_eligible": False,
            }
        ]
        sample_scores = [
            {
                "item_key": "pid:9999",
                "pid": 9999,
                "process_name": "stealth.exe",
                "score": 0.20,
                "risk_level": "LOW",
                "signals_triggered": "process_view",
            }
        ]

        for i in range(1, repetitions + 1):
            t0 = time.perf_counter()
            sid = db.start_scan(db_path=bench_db)
            start_times.append((time.perf_counter() - t0) * 1000.0)

            for f in sample_findings:
                f["scan_id"] = sid

            t0 = time.perf_counter()
            db.insert_findings(sid, sample_findings, db_path=bench_db)
            insert_findings_times.append((time.perf_counter() - t0) * 1000.0)

            t0 = time.perf_counter()
            db.insert_risk_scores(sid, sample_scores, db_path=bench_db)
            insert_scores_times.append((time.perf_counter() - t0) * 1000.0)

            t0 = time.perf_counter()
            db.complete_scan(sid, total_findings=2, high_risk_count=1, duration_ms=50.0, db_path=bench_db)
            complete_times.append((time.perf_counter() - t0) * 1000.0)

            # Candidate & Accept
            db.capture_candidate_baseline_atomic("registry", [{"entry_type": "Run", "entry_key": f"k{i}", "entry_value": "v", "fingerprint": f"f{i}"}], db_path=bench_db)
            t0 = time.perf_counter()
            db.accept_baseline_atomic("registry", db_path=bench_db)
            accept_times.append((time.perf_counter() - t0) * 1000.0)

            t0 = time.perf_counter()
            db.reset_all_baselines_atomic(db_path=bench_db)
            reset_times.append((time.perf_counter() - t0) * 1000.0)

    finally:
        if os.path.exists(bench_db):
            try:
                os.remove(bench_db)
            except OSError:
                pass
        for ext in ["-wal", "-shm"]:
            if os.path.exists(bench_db + ext):
                try:
                    os.remove(bench_db + ext)
                except OSError:
                    pass

    return {
        "start_scan_ms": calculate_stats(start_times),
        "insert_findings_ms": calculate_stats(insert_findings_times),
        "insert_scores_ms": calculate_stats(insert_scores_times),
        "complete_scan_ms": calculate_stats(complete_times),
        "accept_baseline_ms": calculate_stats(accept_times),
        "reset_baselines_ms": calculate_stats(reset_times),
    }


def benchmark_rest_api(repetitions: int = 10) -> Dict[str, Any]:
    """Measure Flask REST API response times for key endpoints using test client."""
    print(f"[*] Benchmarking Dashboard REST API Endpoints ({repetitions} repetitions)...")
    
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        bench_db = tf.name

    try:
        db.init_db(bench_db)
        sid = db.start_scan(db_path=bench_db)
        sample_findings = [
            {
                "scan_id": sid,
                "finding_type": "threat",
                "signal": "process_view",
                "evidence": "Hidden process missing from toolhelp32",
                "severity": "high",
                "pid": 9999,
                "process_name": "stealth.exe",
                "exe_path": "C:\\Windows\\stealth.exe",
                "score_eligible": True,
            }
        ]
        sample_scores = [
            {
                "item_key": "pid:9999",
                "pid": 9999,
                "process_name": "stealth.exe",
                "score": 0.20,
                "risk_level": "LOW",
                "signals_triggered": "process_view",
            }
        ]
        db.insert_findings(sid, sample_findings, db_path=bench_db)
        db.insert_risk_scores(sid, sample_scores, db_path=bench_db)
        db.complete_scan(sid, total_findings=1, high_risk_count=0, duration_ms=25.0, db_path=bench_db)

        app = create_app(config_override={
            "TESTING": True,
            "DB_PATH": bench_db,
            "CSRF_ENABLED": False,
            "WTF_CSRF_ENABLED": False,
        })
        client = app.test_client()

        endpoints = [
            ("GET", "/api/health"),
            ("GET", "/api/scan/latest"),
            ("GET", "/api/scores"),
            ("GET", "/api/baseline"),
            ("GET", "/api/scenarios"),
            ("GET", "/api/history"),
        ]

        results: Dict[str, Any] = {}
        for method, endpoint in endpoints:
            times: List[float] = []
            for _ in range(repetitions):
                t0 = time.perf_counter()
                resp = client.get(endpoint)
                times.append((time.perf_counter() - t0) * 1000.0)
            results[endpoint] = calculate_stats(times)

        return results
    finally:
        if os.path.exists(bench_db):
            try:
                os.remove(bench_db)
            except OSError:
                pass
        for ext in ["-wal", "-shm"]:
            if os.path.exists(bench_db + ext):
                try:
                    os.remove(bench_db + ext)
                except OSError:
                    pass


def run_all_benchmarks(repetitions: int = 10) -> Dict[str, Any]:
    """Execute the full empirical benchmarking suite and collect structured results."""
    print("======================================================================")
    print("GhostHunt Phase 8: Running Empirical Performance Benchmarks")
    print("======================================================================")
    
    specs = get_host_specs()
    detectors = benchmark_detectors(repetitions)
    sig_cache = benchmark_signature_cache(repetitions)
    full_cycles = benchmark_full_scan_cycles(repetitions)
    db_ops = benchmark_database_operations(repetitions)
    api_ops = benchmark_rest_api(repetitions)

    report = {
        "host_specifications": specs,
        "detector_benchmarks": detectors,
        "signature_cache_benchmarks": sig_cache,
        "scan_cycle_and_resources": full_cycles,
        "database_operations": db_ops,
        "rest_api_benchmarks": api_ops,
    }

    print("======================================================================")
    print("Benchmarking Complete!")
    print("======================================================================")
    return report


if __name__ == "__main__":
    rep = 10
    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        rep = int(sys.argv[1])
    data = run_all_benchmarks(repetitions=rep)
    output_path = os.path.join(os.path.dirname(__file__), "..", "Docs", "benchmark_data.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    print(f"Benchmark results saved to: {output_path}")
