/**
 * GhostHunt — Simulation SSE Client
 *
 * Consumes /api/simulations/stream/<scenario_id> via EventSource and renders a
 * live, timestamped log with a progress bar inside the simulation modal.
 *
 * Protocol contract (server side, dashboard/routes.py):
 *   Frames are UNNAMED SSE messages — `data: {...}\n\n` only, no `event:` line.
 *   The event kind is carried in the payload's "type" field, so every frame is
 *   delivered to EventSource.onmessage. Registering named listeners instead
 *   would silently receive nothing.
 *
 * Terminal frames: "complete" (success) or "error" (failure). After either one
 * the client closes the stream itself; EventSource must never be allowed to
 * auto-reconnect into a second scenario run.
 */

// The one live stream. Kept at module scope so Cancel can actually abort it and
// so a second Run cannot open a parallel stream writing into the same log.
let currentStream = null;
let autoCloseTimer = null;

/**
 * Returns the log container and guarantees the empty-state placeholder is gone.
 */
function getLogContainer() {
    return document.getElementById('sim-log');
}

function clearLog() {
    const logContainer = getLogContainer();
    if (!logContainer) return;
    logContainer.innerHTML = '';
}

function updateLog(message, type) {
    const logContainer = getLogContainer();
    if (!logContainer) return;

    const now = new Date();
    const stamp = now.toLocaleTimeString([], {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
    });

    const entry = document.createElement('div');
    entry.className = 'simulation-log-entry ' + (type || '');

    const timeEl = document.createElement('span');
    timeEl.className = 'simulation-log-time';
    timeEl.textContent = stamp;

    const msgEl = document.createElement('span');
    msgEl.className = 'simulation-log-message';
    msgEl.textContent = message;

    entry.appendChild(timeEl);
    entry.appendChild(msgEl);
    logContainer.appendChild(entry);

    // Auto-scroll to newest entry.
    logContainer.scrollTop = logContainer.scrollHeight;
}

/**
 * Stops any in-flight stream and resets transient UI state.
 * Called by the Cancel button, the X button, and on auto-close.
 */
function closeSimulationModal() {
    if (autoCloseTimer) {
        clearTimeout(autoCloseTimer);
        autoCloseTimer = null;
    }

    if (currentStream) {
        // Mark as intentional so onerror stays silent during teardown.
        currentStream.__ghosthuntClosed = true;
        try {
            currentStream.close();
        } catch (e) {
            /* already closed */
        }
        currentStream = null;
    }

    const overlay = document.getElementById('simulation-modal-overlay');
    if (overlay) overlay.style.display = 'none';
}

function resetModalState() {
    clearLog();

    const progressFill = document.getElementById('sim-progress-fill');
    if (progressFill) progressFill.style.width = '0%';

    const phaseEl = document.getElementById('sim-phase');
    if (phaseEl) phaseEl.textContent = 'Connecting…';

    const titleEl = document.getElementById('simulation-modal-title');
    if (titleEl) titleEl.textContent = 'Simulation Progress';
}

/**
 * Formats a millisecond duration for display.
 *
 * Accumulating float `duration_ms` values with `+=` produces IEEE-754 drift
 * (e.g. 4309.820000000001). Rounding here keeps the card readable and stops a
 * 21-character value from being clipped inside a narrow metric card.
 */
function formatDuration(ms) {
    const safe = Number.isFinite(ms) ? Math.max(0, ms) : 0;
    return safe >= 1000
        ? (safe / 1000).toFixed(2) + ' s'
        : safe.toFixed(2) + ' ms';
}

/**
 * Renders the execution summary card that survives modal close.
 */
function renderSummary(summary) {
    const card = document.getElementById('simulation-summary-card');
    if (!card) return;

    const set = (id, value) => {
        const el = document.getElementById(id);
        if (el) el.textContent = value;
    };

    set('summary-total', summary.total);
    set('summary-passed', summary.passed);
    set('summary-failed', summary.failed);
    set('summary-duration', formatDuration(summary.durationMs));

    const badge = document.getElementById('summary-status-badge');
    if (badge) {
        const allPassed = summary.failed === 0 && summary.total > 0;
        badge.textContent = allPassed ? 'ALL PASSED' : summary.failed + ' FAILED';
        badge.className = 'badge ' + (allPassed ? 'badge-success' : 'badge-danger');
    }

    card.style.display = 'block';
}

function setProgress(value) {
    const progressFill = document.getElementById('sim-progress-fill');
    if (!progressFill) return;
    const clamped = Math.max(0, Math.min(100, Number(value) || 0));
    progressFill.style.width = clamped + '%';
}

/**
 * Runs one scenario, or every scenario when scenarioId === 'all'.
 * Opens the modal, streams progress, then auto-closes with a summary.
 */
function runSimulation(scenarioId) {
    const overlay = document.getElementById('simulation-modal-overlay');
    if (!overlay) {
        console.error('simulations.js: #simulation-modal-overlay not found');
        return;
    }

    // Never allow two concurrent streams into one log.
    if (currentStream) closeSimulationModal();

    resetModalState();
    overlay.style.display = 'flex';

    const titleEl = document.getElementById('simulation-modal-title');
    if (titleEl) {
        titleEl.textContent =
            scenarioId === 'all' ? 'Running All Scenarios' : 'Running ' + scenarioId;
    }

    updateLog('Connecting to simulation stream…', 'log-info');

    // Accumulated run state for the closing summary.
    const summary = { total: 0, passed: 0, failed: 0, durationMs: 0 };
    let finished = false;

    const eventSource = new EventSource(
        '/api/simulations/stream/' + encodeURIComponent(scenarioId)
    );
    currentStream = eventSource;

    const finish = (ok, headline) => {
        if (finished) return;
        finished = true;

        setProgress(100);

        const phaseEl = document.getElementById('sim-phase');
        if (phaseEl) phaseEl.textContent = headline;

        renderSummary(summary);
        updateLog(headline, ok ? 'log-success' : 'log-error');

        eventSource.__ghosthuntClosed = true;
        try {
            eventSource.close();
        } catch (e) {
            /* already closed */
        }
        if (currentStream === eventSource) currentStream = null;

        // Let the operator read the tail of the log, then get out of the way.
        // Only auto-close if no newer run has taken over the modal.
        autoCloseTimer = setTimeout(() => {
            autoCloseTimer = null;
            if (currentStream === null) closeSimulationModal();
        }, ok ? 2200 : 5000);
    };

    eventSource.onopen = () => {
        if (eventSource.__ghosthuntClosed) return;
        updateLog('Stream connected.', 'log-info');
    };

    eventSource.onmessage = (e) => {
        // A superseded stream must never write into the new run's log.
        if (eventSource.__ghosthuntClosed) return;

        let data;
        try {
            data = JSON.parse(e.data);
        } catch (err) {
            console.error('simulations.js: bad SSE payload', e.data);
            return;
        }

        switch (data.type) {
            case 'phase': {
                const phaseEl = document.getElementById('sim-phase');
                if (phaseEl) {
                    phaseEl.textContent =
                        (data.phase ? data.phase + ' — ' : '') + (data.message || '');
                }
                if (typeof data.progress === 'number') setProgress(data.progress);
                updateLog(data.message || data.phase || '', 'log-phase');
                break;
            }

            case 'step': {
                if (typeof data.progress === 'number') setProgress(data.progress);
                updateLog(data.message || '', 'log-step');
                break;
            }

            case 'result': {
                // Single-scenario terminal payload: the result is nested.
                const r = data.result || {};
                summary.total = 1;
                summary.passed = r.passed ? 1 : 0;
                summary.failed = r.passed ? 0 : 1;
                summary.durationMs = r.duration_ms || 0;

                if (r.passed) {
                    updateLog(
                        'PASSED — ' + r.name + ' (' + r.duration_ms + ' ms)',
                        'log-success'
                    );
                } else {
                    updateLog(
                        'FAILED — ' + (r.name || r.scenario_id) + ': ' +
                            (r.error || 'unknown error'),
                        'log-error'
                    );
                }
                setProgress(typeof data.progress === 'number' ? data.progress : 100);
                break;
            }

            case 'step_result': {
                // Batch-mode per-scenario result.
                const r = data.result || {};
                summary.total += 1;
                if (r.passed) summary.passed += 1;
                else summary.failed += 1;
                summary.durationMs += r.duration_ms || 0;

                if (r.passed) {
                    updateLog(
                        '[' + r.scenario_id + '] PASSED — ' + r.duration_ms + ' ms',
                        'log-success'
                    );
                } else {
                    updateLog(
                        '[' + r.scenario_id + '] FAILED — ' + (r.error || 'unknown error'),
                        'log-error'
                    );
                }
                if (typeof data.progress === 'number') setProgress(data.progress);
                break;
            }

            case 'batch_result': {
                summary.total = data.total || summary.total;
                summary.passed = data.passed || summary.passed;
                summary.failed = data.failed || summary.failed;
                updateLog(
                    'Batch complete — ' + data.passed + '/' + data.total + ' passed',
                    'log-result'
                );
                setProgress(100);
                break;
            }

            case 'complete': {
                const headline =
                    summary.total > 0
                        ? summary.passed + '/' + summary.total + ' scenarios passed'
                        : 'Completed';
                finish(summary.failed === 0, headline);
                break;
            }

            case 'error': {
                updateLog('ERROR — ' + (data.message || 'stream failed'), 'log-error');
                finish(false, 'Failed: ' + (data.message || 'unknown error'));
                break;
            }

            default: {
                updateLog(data.message || JSON.stringify(data), 'log-info');
                break;
            }
        }
    };

    eventSource.onerror = () => {
        // A closed stream is not necessarily an error: EventSource reports
        // readyState CLOSED and fires onerror whenever the server ends the
        // response. Only treat it as a failure if we never saw a terminal frame.
        if (eventSource.__ghosthuntClosed || finished) return;

        // readyState 0 (CONNECTING) means the browser will retry; a transient
        // blip is not worth alarming the operator about on localhost.
        if (eventSource.readyState === EventSource.CONNECTING) {
            updateLog('Stream interrupted — reconnecting…', 'log-info');
            return;
        }

        updateLog('Connection lost before completion.', 'log-error');
        finish(false, 'Connection lost');
    };
}
