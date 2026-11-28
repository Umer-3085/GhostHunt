/**
 * GhostHunt — Dashboard Client Script
 * Implements 5s asynchronous polling, manual scan trigger, HTTP 409 conflict handling,
 * live entity search & severity filtering, and baseline review & reset actions with CSRF protection.
 * Day 1 UI Polish: Scheduler ETA countdown, Skeleton loaders, Enhanced toast system with actions & persistence.
 * Day 2 UI Polish: Scan progress panel, Notification bell, Keyboard shortcuts, Help overlay.
 */

let currentSeverityFilter = 'ALL';
let schedulerIntervalId = null;
let scanProgressIntervalId = null;
let toastHistory = [];

// Retrieve CSRF token from page meta tag
function getCsrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute('content') : '';
}

// Toast notification helper with action support and localStorage persistence
function showToast(message, type = 'info', durationMs = 4000, action = null) {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;

    let icon = 'ℹ️';
    if (type === 'success') icon = '✓';
    if (type === 'warning') icon = '⚠️';
    if (type === 'danger') icon = '✕';

    const iconSpan = document.createElement('span');
    iconSpan.textContent = icon;
    const msgSpan = document.createElement('span');
    msgSpan.textContent = message;

    toast.appendChild(iconSpan);
    toast.appendChild(msgSpan);

    // Add action button if provided
    if (action) {
        const actionBtn = document.createElement('button');
        actionBtn.className = 'toast-action btn btn-secondary btn-sm';
        actionBtn.textContent = action.label;
        actionBtn.onclick = () => {
            action.callback();
            toast.remove();
        };
        toast.appendChild(actionBtn);
    }

    container.appendChild(toast);

    // Persist to localStorage
    const toastRecord = {
        id: Date.now() + Math.random(),
        message,
        type,
        timestamp: new Date().toISOString(),
        action: action ? action.label : null
    };
    toastHistory.unshift(toastRecord);
    if (toastHistory.length > 50) toastHistory.pop();
    localStorage.setItem('ghosthunt_toast_history', JSON.stringify(toastHistory));

    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(100%)';
        toast.style.transition = 'all 0.3s ease';
        setTimeout(() => toast.remove(), 300);
    }, durationMs);
}

// Load toast history from localStorage on startup
function loadToastHistory() {
    try {
        const stored = localStorage.getItem('ghosthunt_toast_history');
        if (stored) {
            toastHistory = JSON.parse(stored);
        }
    } catch (e) {
        // Ignore parse errors
    }
    // Clear old "busy" toasts on load so they don't reappear
    toastHistory = toastHistory.filter(t => !t.message?.includes('in progress'));
    localStorage.setItem('ghosthunt_toast_history', JSON.stringify(toastHistory));
}

// Clear toast history
function clearToastHistory() {
    toastHistory = [];
    localStorage.removeItem('ghosthunt_toast_history');
}

// Combined severity + search filter for entities table
function applyEntityFilters() {
    const searchInput = document.getElementById('entity-search');
    const query = searchInput ? searchInput.value.trim().toLowerCase() : '';
    const rows = document.querySelectorAll('.entity-row');
    let visibleCount = 0;

    rows.forEach(row => {
        const rowSeverity = row.getAttribute('data-severity');
        const rowSearch = row.getAttribute('data-search') || row.textContent.toLowerCase();
        const matchesSeverity = currentSeverityFilter === 'ALL' || rowSeverity === currentSeverityFilter;
        const matchesSearch = !query || rowSearch.includes(query);

        const nextRow = row.nextElementSibling;
        const isWaterfall = nextRow && nextRow.classList.contains('waterfall-row');

        if (matchesSeverity && matchesSearch) {
            row.style.display = '';
            visibleCount++;
        } else {
            row.style.display = 'none';
            if (isWaterfall) {
                nextRow.classList.add('hidden');
                nextRow.classList.remove('is-expanded');
                row.classList.remove('is-expanded');
                row.setAttribute('aria-expanded', 'false');
                nextRow.setAttribute('aria-hidden', 'true');
            }
        }
    });

    const countBadge = document.getElementById('visible-entity-count');
    if (countBadge) {
        countBadge.textContent = `${visibleCount} ${visibleCount === 1 ? 'entity' : 'entities'}`;
    }
}

// Filter entities table by severity
function filterEntities(severity, buttonElement) {
    currentSeverityFilter = severity;
    const buttons = document.querySelectorAll('.btn-filter');
    buttons.forEach(btn => btn.classList.remove('active'));
    if (buttonElement) buttonElement.classList.add('active');
    applyEntityFilters();
}

const SCAN_BTN_IDLE_HTML = `
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
        <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon>
    </svg>
    <span>Run Scan</span>
`;

// Trigger manual scan cycle (Asynchronous with 1s phase tracking)
async function triggerManualScan() {
    const btn = document.getElementById('btn-manual-scan');
    // Guard: prevent double-submit if scan already in progress
    if (btn && (btn.disabled || scanProgressIntervalId)) {
        return;
    }
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<span class="spin">⟳</span> <span>Scanning...</span>';
    }

    // Reset dismissal guard for new scan
    dismissedScanProgressId = null;
    if (scanProgressDismissTimer) {
        clearTimeout(scanProgressDismissTimer);
        scanProgressDismissTimer = null;
    }

    // Start 1s progress polling immediately
    startScanProgressPolling();

    try {
        const response = await fetch('/api/scan?async=true', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': getCsrfToken(),
                'X-Async-Scan': 'true',
            },
            body: JSON.stringify({ async: true }),
        });

        const data = await response.json();

        if (response.status === 409) {
            // Concurrency Guard Conflict — silent, progress panel shows state
            console.debug('Manual scan 409: another operation in progress');
            stopScanProgressPolling();
            if (btn) {
                btn.disabled = false;
                btn.innerHTML = SCAN_BTN_IDLE_HTML;
            }
        } else if (response.ok) {
            showToast('Scan initiated. Tracking phases…', 'info', 3000);
            // Polling will handle completion and reset the button
        } else {
            showToast(data.message || 'Scan execution failed to start.', 'danger');
            stopScanProgressPolling();
            if (btn) {
                btn.disabled = false;
                btn.innerHTML = SCAN_BTN_IDLE_HTML;
            }
        }
    } catch (err) {
        showToast(`Network or server error: ${err.message}`, 'danger');
        stopScanProgressPolling();
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = SCAN_BTN_IDLE_HTML;
        }
    }
}

// Baseline Management: Accept Candidate Baseline
async function acceptBaseline(category = null) {
    try {
        const payload = category ? { category: category } : {};
        const response = await fetch('/api/baseline/accept', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': getCsrfToken(),
            },
            body: JSON.stringify(payload),
        });

        const data = await response.json();

        if (response.status === 409) {
            showToast('Busy — try again in a moment.', 'warning', 2000);
        } else if (response.ok && data.success) {
            showToast(`Baseline for ${category || 'all categories'} accepted as trusted reference.`, 'success', 4000, {
                label: 'Reload',
                callback: () => window.location.reload()
            });
        } else {
            showToast(data.message || 'Baseline acceptance failed.', 'danger');
        }
    } catch (err) {
        showToast(`Baseline accept error: ${err.message}`, 'danger');
    }
}

// Baseline Reset Modal Controls
function confirmResetBaseline() {
    const modal = document.getElementById('reset-modal');
    if (modal) modal.classList.remove('hidden');
}

function closeResetModal() {
    const modal = document.getElementById('reset-modal');
    if (modal) modal.classList.add('hidden');
}

async function executeResetBaseline() {
    closeResetModal();
    try {
        const response = await fetch('/api/baseline/reset', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': getCsrfToken(),
            },
            body: JSON.stringify({ confirm: true }),
        });

        const data = await response.json();

        if (response.status === 409) {
            showToast('Busy — try again in a moment.', 'warning', 2000);
        } else if (response.ok && data.success) {
            showToast('Baselines reset successfully to NOT_INITIALIZED.', 'success', 4000, {
                label: 'Reload',
                callback: () => window.location.reload()
            });
        } else {
            showToast(data.message || 'Baseline reset failed.', 'danger');
        }
    } catch (err) {
        showToast(`Reset error: ${err.message}`, 'danger');
    }
}

// Skeleton loader injection for tables
function showTableSkeleton(tableId, rowCount = 5, colCount = 7) {
    const table = document.getElementById(tableId);
    if (!table) return;
    const tbody = table.querySelector('tbody');
    if (!tbody || tbody.children.length > 0) return;
    tbody.innerHTML = '';
    for (let i = 0; i < rowCount; i++) {
        const tr = document.createElement('tr');
        tr.className = 'skeleton-row';
        for (let j = 0; j < colCount; j++) {
            const td = document.createElement('td');
            td.style.height = '40px';
            tr.appendChild(td);
        }
        tbody.appendChild(tr);
    }
}

function showCardSkeleton(cardSelector, count = 4) {
    const container = document.querySelector(cardSelector);
    if (!container) return;
    // Only add skeletons if container is empty (initial load)
    if (container.children.length === 0) {
        for (let i = 0; i < count; i++) {
            const div = document.createElement('div');
            div.className = 'skeleton-card';
            container.appendChild(div);
        }
    }
}

function removeSkeletons(tableId, cardSelector) {
    const table = document.getElementById(tableId);
    if (table) {
        const tbody = table.querySelector('tbody');
        if (tbody) {
            tbody.querySelectorAll('.skeleton-row').forEach(el => el.remove());
        }
    }
    if (cardSelector) {
        const container = document.querySelector(cardSelector);
        if (container) {
            container.querySelectorAll('.skeleton-card').forEach(el => el.remove());
        }
    }
}

// Format time duration for scheduler ETA
function formatDuration(seconds) {
    if (seconds < 60) return `${seconds}s`;
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    if (mins < 60) return `${mins}m ${secs}s`;
    const hours = Math.floor(mins / 60);
    const remainingMins = mins % 60;
    return `${hours}h ${remainingMins}m`;
}

// Update scheduler ETA countdown — runs once per poll, actual countdown via requestAnimationFrame
let _etaCountdownId = null;
let _etaNextScanMs = null;

function updateSchedulerEta(data) {
    const etaEl = document.getElementById('scheduler-eta');
    if (!etaEl) return;

    if (!data.scheduler || !data.scheduler.is_running) {
        etaEl.textContent = 'Next scan: —';
        etaEl.style.display = 'none';
        _etaNextScanMs = null;
        return;
    }

    const interval = data.scheduler.interval_seconds || 300;

    let lastScanMs = null;
    if (data.latest_scan && data.latest_scan.scan_time) {
        lastScanMs = new Date(data.latest_scan.scan_time.replace(' ', 'T')).getTime();
    } else if (data.scheduler.last_scan_time) {
        lastScanMs = new Date(data.scheduler.last_scan_time * 1000).getTime();
    }

    if (!lastScanMs) {
        etaEl.textContent = 'Next scan: calculating...';
        etaEl.style.display = 'inline-flex';
        return;
    }

    _etaNextScanMs = lastScanMs + interval * 1000;
    etaEl.style.display = 'inline-flex';

    // Start countdown ticker if not already running
    if (!_etaCountdownId) {
        const tick = () => {
            if (!_etaNextScanMs) return;
            const remaining = Math.max(0, Math.round((_etaNextScanMs - Date.now()) / 1000));
            const el = document.getElementById('scheduler-eta');
            if (!el) { _etaCountdownId = null; return; }
            if (remaining <= 0) {
                el.textContent = 'Scan overdue…';
                el.classList.add('text-warning');
            } else {
                el.textContent = `Next scan in: ${formatDuration(remaining)}`;
                el.classList.remove('text-warning');
            }
            _etaCountdownId = setTimeout(tick, 1000);
        };
        tick();
    }
}

// Asynchronous 5-Second Status Poller (FR-6.6)
let lastKnownScanId = null;

async function pollStatus() {
    try {
        const response = await fetch('/api/status');
        if (!response.ok) return;

        const data = await response.json();

        // Update scheduler status indicator — shows ACTIVE only when scan is actually running
        const schedIndicator = document.getElementById('scheduler-indicator');
        if (schedIndicator && data.scheduler) {
            const scanActive = data.scan_progress && data.scan_progress.phase !== 'idle' && data.scan_progress.phase !== 'complete';
            if (data.scheduler.is_running) {
                if (scanActive) {
                    schedIndicator.className = 'scheduler-badge running';
                    schedIndicator.querySelector('.label').textContent = 'Scanner: ACTIVE';
                } else {
                    schedIndicator.className = 'scheduler-badge idle';
                    schedIndicator.querySelector('.label').textContent = 'Scheduler: STANDBY';
                }
            } else {
                schedIndicator.className = 'scheduler-badge idle';
                schedIndicator.querySelector('.label').textContent = 'Scheduler: STOPPED';
            }
        }

        // Update scheduler ETA countdown
        updateSchedulerEta(data);
        if (window.TimelineCard) {
            TimelineCard.updateEta(data);
        }

        // Check for active scan progress (from scheduler or manual)
        if (data.scan_progress) {
            const sp = data.scan_progress;
            if (sp.phase === 'idle' || (sp.phase === 'complete' && dismissedScanProgressId === sp.scan_id)) {
                const panel = document.getElementById('scan-progress-panel');
                if (panel) panel.classList.remove('visible');
                stopScanProgressPolling();
            } else {
                updateScanProgressPanel(sp);
                if (sp.phase !== 'complete') {
                    startScanProgressPolling();
                }
            }
        }

        // Detect new completed scan on main dashboard page
        if (data.latest_completed_scan_id !== undefined && data.latest_completed_scan_id !== null) {
            if (lastKnownScanId === null) {
                lastKnownScanId = data.latest_completed_scan_id;
            } else if (data.latest_completed_scan_id > lastKnownScanId) {
                const prevId = lastKnownScanId;
                lastKnownScanId = data.latest_completed_scan_id;
                if (window.location.pathname === '/') {
                    showToast(`New scan #${data.latest_completed_scan_id} completed.`, 'success', 4000);
                    // Start entity delta polling (Issue #8)
                    startEntityDeltaPolling(data.latest_completed_scan_id, prevId);
                    if (window.TimelineCard) TimelineCard.load();
                }
                // Scan completed — stop any stale progress polling and reset button
                stopScanProgressPolling();
            }
        }
    } catch (e) {
        // Silent polling failure to avoid annoying user during transient server restart
    }
}

// Start 5s interval and keyboard shortcuts on DOM load
document.addEventListener('DOMContentLoaded', () => {
    loadToastHistory();

    // Sync UI with server scan state on load
    syncScanStateOnLoad();

    // Show skeleton loaders on initial load for main dashboard
    if (window.location.pathname === '/') {
        showTableSkeleton('entities-table', 5, 7);
        showCardSkeleton('.metrics-grid', 4);
        if (window.TimelineCard) {
            TimelineCard.init();
        }
    }

    if (window.SignalWaterfall) {
        SignalWaterfall.init();
    }

    pollStatus();
    schedulerIntervalId = setInterval(pollStatus, 5000);

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            closeResetModal();
            if (window.BaselineVisualDiff) {
                BaselineVisualDiff.closeModal();
            }
        }
    });

    
    // Clean up skeleton loaders after first successful poll
    setTimeout(() => {
        removeSkeletons('entities-table', '.metrics-grid');
    }, 6000);

    // Initialize notification bell
    initNotificationBell();

    // Initialize keyboard shortcuts
    initKeyboardShortcuts();
});

// ===========================================================================
// Sync UI with server scan state on page load
// ===========================================================================
async function syncScanStateOnLoad() {
    try {
        const response = await fetch('/api/scan/progress');
        if (!response.ok) return;
        const data = await response.json();
        const progress = data.progress;
        if (progress && progress.phase !== 'idle' && progress.phase !== 'complete') {
            // Server scan is running — start progress polling and disable button
            const btn = document.getElementById('btn-manual-scan');
            if (btn) {
                btn.disabled = true;
                btn.innerHTML = '<span class="spin">⟳</span> <span>Scanning...</span>';
            }
            startScanProgressPolling();
            updateScanProgressPanel(progress);
        } else {
            // No scan running — ensure button enabled
            const btn = document.getElementById('btn-manual-scan');
            if (btn) {
                btn.disabled = false;
                btn.innerHTML = SCAN_BTN_IDLE_HTML;
            }
        }
    } catch (e) {
        // Silent failure — button stays enabled by default
    }
}

// ===========================================================================
// Scan Progress Panel (Day 2)
// ===========================================================================
let dismissedScanProgressId = null;
let scanProgressDismissTimer = null;

async function pollScanProgress() {
    try {
        const response = await fetch('/api/scan/progress');
        if (!response.ok) return;

        const data = await response.json();
        updateScanProgressPanel(data.progress);
    } catch (e) {
        // Silent failure
    }
}

function updateScanProgressPanel(progress) {
    const panel = document.getElementById('scan-progress-panel');
    const fill = document.getElementById('scan-progress-fill');
    const label = document.getElementById('scan-progress-label');
    const phases = document.querySelectorAll('#scan-progress-phases .phase-pill');

    if (!panel || !fill || !label) return;

    const phase = progress.phase || 'idle';
    const pct = progress.progress || 0;
    const scanId = progress.scan_id;

    if (phase === 'idle') {
        panel.classList.remove('visible');
        const bar = panel.querySelector('.scan-progress-bar');
        if (bar) bar.setAttribute('aria-valuenow', 0);
        stopScanProgressPolling();
        return;
    }

    // Guard against completed scan re-appearing on polling
    if (phase === 'complete' && dismissedScanProgressId === scanId) {
        panel.classList.remove('visible');
        stopScanProgressPolling();
        return;
    }

    panel.classList.add('visible');
    fill.style.width = `${pct}%`;
    const bar = panel.querySelector('.scan-progress-bar');
    if (bar) bar.setAttribute('aria-valuenow', pct);

    // Update phase pills
    const phaseOrder = ['process_views', 'persistence', 'signatures', 'correlation', 'complete'];
    const currentIdx = phaseOrder.indexOf(phase);

    phases.forEach((pill) => {
        const pillPhase = pill.dataset.phase;
        const pillIdx = phaseOrder.indexOf(pillPhase);
        pill.classList.remove('active', 'completed');
        if (pillIdx < currentIdx || phase === 'complete') {
            pill.classList.add('completed');
        } else if (pillIdx === currentIdx) {
            pill.classList.add('active');
        }
    });

    // Update label
    const phaseLabels = {
        'process_views': 'Enumerating Processes…',
        'persistence': 'Checking Persistence…',
        'signatures': 'Verifying Signatures…',
        'correlation': 'Correlating Risks…',
        'complete': 'Scan Completed (100%)',
    };
    label.textContent = phaseLabels[phase] || `Scan in progress (${pct}%)`;

    if (phase === 'complete') {
        const btn = document.getElementById('btn-manual-scan');
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = SCAN_BTN_IDLE_HTML;
        }
        if (!scanProgressDismissTimer) {
            scanProgressDismissTimer = setTimeout(() => {
                panel.classList.remove('visible');
                dismissedScanProgressId = scanId;
                stopScanProgressPolling();
                scanProgressDismissTimer = null;
            }, 2500);
        }
    }
}

function startScanProgressPolling() {
    if (scanProgressIntervalId) return;
    pollScanProgress(); // immediate first poll
    scanProgressIntervalId = setInterval(pollScanProgress, 1000);
}

function stopScanProgressPolling() {
    if (scanProgressIntervalId) {
        clearInterval(scanProgressIntervalId);
        scanProgressIntervalId = null;
    }
    if (scanProgressDismissTimer) {
        clearTimeout(scanProgressDismissTimer);
        scanProgressDismissTimer = null;
    }
    const btn = document.getElementById('btn-manual-scan');
    if (btn && btn.disabled) {
        btn.disabled = false;
        btn.innerHTML = SCAN_BTN_IDLE_HTML;
    }
}

// Safety net: ensure button state matches actual scan state every 5s
setInterval(() => {
    const btn = document.getElementById('btn-manual-scan');
    if (!btn) return;
    // If no progress polling active and no scan in progress per UI, ensure button enabled
    if (!scanProgressIntervalId && !scanProgressDismissTimer) {
        const panel = document.getElementById('scan-progress-panel');
        const isScanActive = panel && panel.classList.contains('visible');
        if (!isScanActive && btn.disabled) {
            btn.disabled = false;
            btn.innerHTML = SCAN_BTN_IDLE_HTML;
        }
    }
}, 5000);

// ===========================================================================
// Notification Bell (Day 2)
// ===========================================================================

function initNotificationBell() {
    const bell = document.getElementById('notification-bell');
    const dropdown = document.getElementById('notification-dropdown');
    const badge = document.getElementById('notification-badge');
    const list = document.getElementById('notification-list');
    const empty = document.getElementById('notification-empty');
    const clearBtn = document.getElementById('clear-notifications');

    if (!bell || !dropdown) return;

    // Toggle dropdown
    bell.addEventListener('click', (e) => {
        e.stopPropagation();
        const isOpen = dropdown.style.display !== 'none';
        dropdown.style.display = isOpen ? 'none' : 'block';
        bell.setAttribute('aria-expanded', !isOpen);
        if (!isOpen) {
            renderNotificationList();
        }
    });

    // Close on outside click
    document.addEventListener('click', (e) => {
        if (!bell.contains(e.target) && !dropdown.contains(e.target)) {
            dropdown.style.display = 'none';
            bell.setAttribute('aria-expanded', 'false');
        }
    });

    // Clear all
    if (clearBtn) {
        clearBtn.addEventListener('click', () => {
            clearToastHistory();
            renderNotificationList();
            updateNotificationBadge();
        });
    }

    // Initial render
    updateNotificationBadge();
}

function renderNotificationList() {
    const list = document.getElementById('notification-list');
    const empty = document.getElementById('notification-empty');
    if (!list) return;

    list.innerHTML = '';

    if (toastHistory.length === 0) {
        list.style.display = 'none';
        if (empty) empty.style.display = 'block';
        return;
    }

    list.style.display = 'block';
    if (empty) empty.style.display = 'none';

    toastHistory.slice(0, 20).forEach(toast => {
        const item = document.createElement('div');
        item.className = `notification-item notification-${toast.type}`;
        item.setAttribute('role', 'listitem');

        const time = new Date(toast.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        const icons = { success: '✓', warning: '⚠', danger: '✕', info: 'ℹ' };

        item.innerHTML = `
            <span class="notification-icon">${icons[toast.type] || 'ℹ'}</span>
            <div class="notification-content">
                <span class="notification-message">${escapeHtml(toast.message)}</span>
                <span class="notification-time">${time}</span>
            </div>
        `;
        list.appendChild(item);
    });
}

function updateNotificationBadge() {
    const badge = document.getElementById('notification-badge');
    if (!badge) return;

    const unreadCount = toastHistory.length;
    if (unreadCount > 0) {
        badge.textContent = unreadCount > 99 ? '99+' : unreadCount;
        badge.style.display = 'flex';
    } else {
        badge.style.display = 'none';
    }
}

// ===========================================================================
// Live Entity Delta Updates (Issue #8)
// ===========================================================================
let entityDeltaPollInterval = null;
let entityDeltaPollTimeout = null;
let lastNotifiedDeltaScanId = null;

function startEntityDeltaPolling(currentScanId, sinceScanId) {
    stopEntityDeltaPolling();

    // Fetch and apply initial delta immediately
    pollEntityDeltas(currentScanId, sinceScanId);

    // Poll every 10s for deltas
    entityDeltaPollInterval = setInterval(() => {
        pollEntityDeltas(currentScanId, sinceScanId);
    }, 10000);

    // Stop polling after 60s
    entityDeltaPollTimeout = setTimeout(() => {
        stopEntityDeltaPolling();
    }, 60000);
}

function stopEntityDeltaPolling() {
    if (entityDeltaPollInterval) {
        clearInterval(entityDeltaPollInterval);
        entityDeltaPollInterval = null;
    }
    if (entityDeltaPollTimeout) {
        clearTimeout(entityDeltaPollTimeout);
        entityDeltaPollTimeout = null;
    }
}

// Stop polling when user navigates away or tab is hidden
window.addEventListener('beforeunload', stopEntityDeltaPolling);
window.addEventListener('pagehide', stopEntityDeltaPolling);
document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'hidden') {
        stopEntityDeltaPolling();
    }
});

async function pollEntityDeltas(currentScanId, sinceScanId) {
    if (window.location.pathname !== '/') return;
    try {
        let url = `/api/entities/delta?scan_id=${encodeURIComponent(currentScanId)}`;
        if (sinceScanId !== null && sinceScanId !== undefined) {
            url += `&since=${encodeURIComponent(sinceScanId)}`;
        }
        const res = await fetch(url);
        if (!res.ok) return;
        const deltaData = await res.json();
        applyEntityDeltaUI(deltaData, currentScanId);
    } catch (e) {
        // Silent delta polling failure
    }
}

function applyEntityDeltaUI(deltaData, currentScanId) {
    const tbody = document.getElementById('entities-tbody');
    if (!tbody) return;

    const newEntities = deltaData.new || [];
    const changedEntities = deltaData.changed || [];
    const removedEntities = deltaData.removed || [];

    const newCount = newEntities.length;
    const changedCount = changedEntities.length;
    const removedCount = removedEntities.length;

    // Toast notification: "X new, Y changed, Z removed entities detected"
    if ((newCount > 0 || changedCount > 0 || removedCount > 0) && lastNotifiedDeltaScanId !== currentScanId) {
        lastNotifiedDeltaScanId = currentScanId;
        showToast(`${newCount} new, ${changedCount} changed, ${removedCount} removed entities detected`, 'info', 5000);
    }

    const prefersReducedMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    function setupDeltaHighlight(row, type, badgeText) {
        row.classList.remove('new', 'changed', 'removed', 'delta-fading');
        const existingBadge = row.querySelector('.delta-badge');
        if (existingBadge) existingBadge.remove();

        row.classList.add(type);

        const badge = document.createElement('span');
        badge.className = `delta-badge ${type}`;
        badge.textContent = badgeText;

        const sevWrapper = row.querySelector('.severity-wrapper');
        if (sevWrapper) {
            sevWrapper.appendChild(badge);
        } else {
            const firstCell = row.cells[0];
            if (firstCell) firstCell.appendChild(badge);
        }

        // Fade after 10s
        setTimeout(() => {
            if (prefersReducedMotion) {
                if (type === 'removed') {
                    row.remove();
                } else {
                    row.classList.remove(type);
                    badge.remove();
                }
            } else {
                row.classList.add('delta-fading');
                badge.style.opacity = '0';
                setTimeout(() => {
                    if (type === 'removed') {
                        row.remove();
                    } else {
                        row.classList.remove(type, 'delta-fading');
                        badge.remove();
                    }
                }, 1000);
            }
        }, 10000);
    }

    function findRow(ent) {
        const pidStr = ent.pid !== null && ent.pid !== undefined ? String(ent.pid) : null;
        if (pidStr !== null && pidStr !== '') {
            const byPid = tbody.querySelector(`tr[data-pid="${pidStr}"]`);
            if (byPid) return byPid;
        }
        if (ent.process_name) {
            return Array.from(tbody.querySelectorAll('tr.entity-row')).find(r => {
                const nameAttr = r.getAttribute('data-process-name');
                return nameAttr === ent.process_name || r.textContent.includes(ent.process_name);
            });
        }
        return null;
    }

    // 1. Process CHANGED entities
    changedEntities.forEach(ent => {
        const row = findRow(ent);
        if (row) {
            const sev = (ent.risk_level || 'low').toLowerCase();
            row.setAttribute('data-severity', ent.risk_level);
            row.setAttribute('data-score', ent.score);
            const sevBadge = row.querySelector('.badge-severity');
            if (sevBadge) {
                sevBadge.className = `badge badge-severity badge-${sev}`;
                sevBadge.textContent = ent.risk_level;
            }
            const scoreNum = row.querySelector('.score-num');
            if (scoreNum) scoreNum.textContent = Number(ent.score).toFixed(2);
            const scoreFill = row.querySelector('.score-bar-fill');
            if (scoreFill) {
                scoreFill.className = `score-bar-fill fill-${sev}`;
                scoreFill.style.width = `${Math.round(ent.score * 100)}%`;
            }
            setupDeltaHighlight(row, 'changed', 'CHANGED');
        }
    });

    // 2. Process NEW entities
    newEntities.forEach((ent, idx) => {
        let row = findRow(ent);
        if (!row) {
            const tr = document.createElement('tr');
            const rowId = `entity-row-dyn-${Date.now()}-${idx}`;
            const panelId = `waterfall-panel-dyn-${Date.now()}-${idx}`;
            const sev = (ent.risk_level || 'low').toLowerCase();
            tr.id = rowId;
            tr.className = `process-row entity-row severity-${sev}`;
            tr.setAttribute('data-severity', ent.risk_level);
            tr.setAttribute('data-pid', ent.pid ?? '');
            tr.setAttribute('data-score', ent.score);
            tr.setAttribute('data-signals', ent.signals_triggered || '');
            tr.setAttribute('data-process-name', ent.process_name || '');
            tr.setAttribute('tabindex', '0');
            tr.setAttribute('role', 'button');
            tr.setAttribute('aria-expanded', 'false');
            tr.setAttribute('aria-controls', panelId);
            tr.setAttribute('data-search', `${ent.process_name} ${ent.pid ?? ''} ${ent.signals_triggered || ''}`.toLowerCase());
            tr.innerHTML = `
                <td class="cell-severity">
                    <div class="severity-wrapper">
                        <button type="button" class="waterfall-chevron-btn" aria-label="Toggle signal breakdown for ${escapeHtml(ent.process_name)}" tabindex="-1">
                            <svg class="waterfall-chevron" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                                <polyline points="6 9 12 15 18 9"></polyline>
                            </svg>
                        </button>
                        <span class="badge badge-severity badge-${sev}">${escapeHtml(ent.risk_level)}</span>
                    </div>
                </td>
                <td>
                    <div class="score-container">
                        <span class="score-num font-mono">${Number(ent.score).toFixed(2)}</span>
                        <div class="score-bar-bg"><div class="score-bar-fill fill-${sev}" style="width: ${Math.round(ent.score * 100)}%;"></div></div>
                    </div>
                </td>
                <td class="font-bold">${escapeHtml(ent.process_name)}</td>
                <td class="font-mono">${ent.pid !== null && ent.pid !== undefined ? ent.pid : '<span class="text-tertiary">None</span>'}</td>
                <td><span class="signal-chip">${escapeHtml(ent.signals_triggered || 'None')}</span></td>
                <td><span class="badge badge-entity-type">${escapeHtml((ent.item_key || '').split(':')[0].toUpperCase() || 'PROC')}</span></td>
                <td style="text-align: right;"><a href="/process/${ent.pid}?scan_id=${currentScanId}" class="btn btn-sm btn-secondary">Evidence →</a></td>
            `;
            tbody.prepend(tr);
            row = tr;
        }
        setupDeltaHighlight(row, 'new', 'NEW');
    });

    // 3. Process REMOVED entities
    removedEntities.forEach((ent, idx) => {
        let row = findRow(ent);
        if (!row) {
            const tr = document.createElement('tr');
            const rowId = `entity-row-dyn-rem-${Date.now()}-${idx}`;
            const sev = (ent.risk_level || 'low').toLowerCase();
            tr.id = rowId;
            tr.className = `process-row entity-row severity-${sev}`;
            tr.setAttribute('data-severity', ent.risk_level);
            tr.setAttribute('data-pid', ent.pid ?? '');
            tr.setAttribute('data-score', ent.score);
            tr.setAttribute('data-signals', ent.signals_triggered || '');
            tr.setAttribute('data-process-name', ent.process_name || '');
            tr.innerHTML = `
                <td class="cell-severity">
                    <div class="severity-wrapper">
                        <span class="badge badge-severity badge-${sev}">${escapeHtml(ent.risk_level)}</span>
                    </div>
                </td>
                <td>
                    <div class="score-container">
                        <span class="score-num font-mono">${Number(ent.score).toFixed(2)}</span>
                        <div class="score-bar-bg"><div class="score-bar-fill fill-${sev}" style="width: ${Math.round(ent.score * 100)}%;"></div></div>
                    </div>
                </td>
                <td class="font-bold">${escapeHtml(ent.process_name)}</td>
                <td class="font-mono">${ent.pid !== null && ent.pid !== undefined ? ent.pid : '<span class="text-tertiary">None</span>'}</td>
                <td><span class="signal-chip">${escapeHtml(ent.signals_triggered || 'None')}</span></td>
                <td><span class="badge badge-entity-type">${escapeHtml((ent.item_key || '').split(':')[0].toUpperCase() || 'PROC')}</span></td>
                <td style="text-align: right;"><span class="text-tertiary font-mono">Removed</span></td>
            `;
            tbody.appendChild(tr);
            row = tr;
        }
        setupDeltaHighlight(row, 'removed', 'REMOVED');
    });

    if (typeof applyEntityFilters === 'function') {
        applyEntityFilters();
    }
}

// Backward compatibility wrapper
async function applyLiveDeltaUpdates(prevScanId, newScanId) {
    startEntityDeltaPolling(newScanId, prevScanId);
}

function animateMetricValue(elemId, targetVal) {
    const el = document.getElementById(elemId);
    if (!el) return;
    el.classList.add('row-updated');
    el.textContent = targetVal;
    setTimeout(() => el.classList.remove('row-updated'), 2000);
}

// ===========================================================================
// Command Palette (Ctrl+K) (Item 10)
// ===========================================================================

const COMMAND_PALETTE_ITEMS = [
    { title: 'Run Manual Scan', category: 'Action', shortcut: 'R', action: () => triggerManualScan(), icon: '⚡' },
    { title: 'Go to Dashboard', category: 'Navigation', shortcut: '1', action: () => window.location.href = '/', icon: '📊' },
    { title: 'Go to System Findings', category: 'Navigation', shortcut: '2', action: () => window.location.href = '/system-findings', icon: '🔍' },
    { title: 'Go to Scan History', category: 'Navigation', shortcut: '3 / H', action: () => window.location.href = '/history', icon: '📜' },
    { title: 'Go to Simulations', category: 'Navigation', shortcut: '4 / S', action: () => window.location.href = '/simulations', icon: '🧪' },
    { title: 'Accept Candidate Baseline', category: 'Baseline', action: () => acceptBaseline(), icon: '✓' },
    { title: 'Reset Persistence Baselines', category: 'Baseline', action: () => confirmResetBaseline(), icon: '↺' },
    { title: 'Toggle Theme', category: 'Preference', shortcut: 'T', action: () => window.toggleTheme(), icon: '🌓' },
    { title: 'Keyboard Shortcuts Help', category: 'Help', shortcut: '?', action: () => showHelpOverlay(), icon: '❓' },
];

let selectedCommandIndex = 0;

function showCommandPalette() {
    const overlay = document.getElementById('command-palette');
    const input = document.getElementById('command-palette-input');
    if (!overlay || !input) return;

    overlay.style.display = 'flex';
    input.value = '';
    renderCommandPaletteList('');
    input.focus();
}

function hideCommandPalette() {
    const overlay = document.getElementById('command-palette');
    if (overlay) overlay.style.display = 'none';
}

function updatePaletteSelection(items) {
    items.forEach((it, idx) => {
        if (idx === selectedCommandIndex) {
            it.classList.add('selected');
            it.scrollIntoView({ block: 'nearest' });
        } else {
            it.classList.remove('selected');
        }
    });
}

function renderCommandPaletteList(filterText = '') {
    const list = document.getElementById('command-palette-list');
    if (!list) return;

    const query = filterText.toLowerCase().trim();
    let items = COMMAND_PALETTE_ITEMS.filter(it => 
        !query || it.title.toLowerCase().includes(query) || it.category.toLowerCase().includes(query)
    );

    // If on dashboard, also search entities table
    if (query && window.location.pathname === '/') {
        const rows = document.querySelectorAll('.entity-row');
        rows.forEach(r => {
            const name = r.querySelector('.font-bold')?.textContent.trim() || '';
            const pid = r.getAttribute('data-pid') || '';
            if (name.toLowerCase().includes(query) || pid.includes(query)) {
                items.push({
                    title: `Jump to: ${name} (PID ${pid})`,
                    category: 'Entity',
                    action: () => {
                        hideCommandPalette();
                        r.scrollIntoView({ behavior: 'smooth', block: 'center' });
                        r.classList.add('row-updated');
                        setTimeout(() => r.classList.remove('row-updated'), 2000);
                    },
                    icon: '🎯'
                });
            }
        });
    }

    selectedCommandIndex = 0;
    list.innerHTML = '';

    if (items.length === 0) {
        list.innerHTML = '<div class="command-palette-empty text-tertiary" style="padding:var(--space-md); text-align:center;">No matching commands or entities</div>';
        return;
    }

    items.forEach((item, idx) => {
        const div = document.createElement('div');
        div.className = `command-palette-item ${idx === 0 ? 'selected' : ''}`;
        div.setAttribute('role', 'option');
        div.innerHTML = `
            <div class="command-palette-item-left">
                <span class="command-palette-icon">${item.icon}</span>
                <span>${escapeHtml(item.title)}</span>
            </div>
            <div style="display:flex; align-items:center; gap:var(--space-xs);">
                ${item.shortcut ? `<kbd class="kbd-badge">${item.shortcut}</kbd>` : ''}
                <span class="command-palette-category">${escapeHtml(item.category)}</span>
            </div>
        `;
        div.onclick = () => {
            hideCommandPalette();
            item.action();
        };
        list.appendChild(div);
    });
}

function initCommandPalette() {
    const input = document.getElementById('command-palette-input');
    if (input) {
        input.addEventListener('input', (e) => {
            renderCommandPaletteList(e.target.value);
        });
    }
}

// ===========================================================================
// Keyboard Shortcuts (Item 10)
// ===========================================================================

function initKeyboardShortcuts() {
    initCommandPalette();
    document.addEventListener('keydown', handleGlobalKeydown);
}

function handleGlobalKeydown(e) {
    // Check for Ctrl+K or Cmd+K
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        const cp = document.getElementById('command-palette');
        if (cp && cp.style.display !== 'none') {
            hideCommandPalette();
        } else {
            showCommandPalette();
        }
        return;
    }

    // Palette navigation when open
    const cp = document.getElementById('command-palette');
    if (cp && cp.style.display !== 'none') {
        const items = cp.querySelectorAll('.command-palette-item');
        if (e.key === 'Escape') {
            e.preventDefault();
            hideCommandPalette();
            return;
        }
        if (e.key === 'ArrowDown') {
            e.preventDefault();
            if (items.length > 0) {
                selectedCommandIndex = (selectedCommandIndex + 1) % items.length;
                updatePaletteSelection(items);
            }
            return;
        }
        if (e.key === 'ArrowUp') {
            e.preventDefault();
            if (items.length > 0) {
                selectedCommandIndex = (selectedCommandIndex - 1 + items.length) % items.length;
                updatePaletteSelection(items);
            }
            return;
        }
        if (e.key === 'Enter') {
            e.preventDefault();
            if (items[selectedCommandIndex]) items[selectedCommandIndex].click();
            return;
        }
        return;
    }

    // Don't trigger single-letter shortcuts when typing in inputs
    const active = document.activeElement;
    if (active && (active.tagName === 'INPUT' || active.tagName === 'TEXTAREA' || active.isContentEditable)) {
        return;
    }

    const key = e.key.toLowerCase();

    switch (key) {
        case 'r':
            e.preventDefault();
            triggerManualScan();
            break;
        case 's':
            e.preventDefault();
            window.location.href = '/simulations';
            break;
        case 'h':
            e.preventDefault();
            window.location.href = '/history';
            break;
        case 't':
            e.preventDefault();
            window.toggleTheme();
            break;
        case '?':
            if (e.shiftKey) {
                e.preventDefault();
                showHelpOverlay();
            }
            break;
        case '1':
            e.preventDefault();
            window.location.href = '/';
            break;
        case '2':
            e.preventDefault();
            window.location.href = '/system-findings';
            break;
        case '3':
            e.preventDefault();
            window.location.href = '/history';
            break;
        case '4':
            e.preventDefault();
            window.location.href = '/simulations';
            break;
        case 'escape':
            closeResetModal();
            hideHelpOverlay();
            hideCommandPalette();
            break;
    }
}

function showHelpOverlay() {
    const overlay = document.getElementById('help-overlay');
    if (overlay) {
        overlay.style.display = 'flex';
        document.body.style.overflow = 'hidden';
    }
}

function hideHelpOverlay() {
    const overlay = document.getElementById('help-overlay');
    if (overlay) {
        overlay.style.display = 'none';
        document.body.style.overflow = '';
    }
}

// ===========================================================================
// Utility
// ===========================================================================

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Override showToast to update notification badge
const originalShowToast = showToast;
showToast = function(message, type = 'info', durationMs = 4000, action = null) {
    originalShowToast(message, type, durationMs, action);
    updateNotificationBadge();
};

// ===========================================================================
// TimelineCard Component (Scheduler Activity & Last 10 Scans Timeline)
// ===========================================================================
const TimelineCard = {
    containerId: 'timeline-container',
    dotsContainerId: 'sched-timeline-dots', // fallback / backward-compat
    etaElementId: 'sched-timeline-next',
    intervalElementId: 'sched-timeline-interval',
    refreshIntervalMs: 15000,
    timerId: null,
    countdownTimerId: null,
    nextScanMs: null,
    isOverdue: false,

    init() {
        const container = document.getElementById(this.containerId) || document.getElementById(this.dotsContainerId);
        if (!container) return;

        this.load();
        this.startAutoRefresh();
        this.startCountdownTicker();
    },

    async load() {
        try {
            const [recentRes, statusRes] = await Promise.all([
                fetch('/api/scans/recent'),
                fetch('/api/status')
            ]);

            if (!recentRes.ok) return;
            const recentData = await recentRes.json();
            // Up to 10 completed scans, reversed so oldest is left, newest is right
            const scans = (recentData.scans || []).slice(0, 10).reverse();

            let statusData = null;
            if (statusRes && statusRes.ok) {
                statusData = await statusRes.json();
            }

            this.render(scans, statusData);
            if (statusData) {
                this.updateEta(statusData);
            }
        } catch (e) {
            console.debug('TimelineCard load error:', e);
        }
    },

    render(scans, statusData) {
        const container = document.getElementById(this.containerId) || document.getElementById(this.dotsContainerId);
        if (!container) return;

        if (!scans || scans.length === 0) {
            container.innerHTML = `
                <div class="timeline-empty text-tertiary">
                    No completed scans recorded yet. Initiate a scan to populate the timeline.
                </div>
            `;
            return;
        }

        const itemsHtml = scans.map((s, index) => {
            const isLatest = index === scans.length - 1;
            const durMs = Number(s.scan_duration_ms || s.duration_ms || 0);
            const durText = durMs >= 1000 ? `${(durMs / 1000).toFixed(1)}s` : `${Math.round(durMs)}ms`;

            // Risk level determination
            const highCount = s.high_risk_count || s.high_count || 0;
            const medCount = s.med_count || 0;
            let riskLevel = 'low';
            let riskDotClass = 'risk-dot-low';
            let riskBadge = '<span class="badge badge-severity badge-low">LOW</span>';

            if (highCount > 0) {
                riskLevel = 'high';
                riskDotClass = 'risk-dot-high';
                riskBadge = `<span class="badge badge-severity badge-high">${highCount} HIGH</span>`;
            } else if (medCount > 0) {
                riskLevel = 'med';
                riskDotClass = 'risk-dot-med';
                riskBadge = `<span class="badge badge-severity badge-medium">MEDIUM</span>`;
            }

            const entityCount = s.entity_count !== undefined ? s.entity_count : (s.total_findings || 0);
            const entityLabel = entityCount === 1 ? '1 entity' : `${entityCount} entities`;

            // Format timestamp
            const rawTime = s.scan_time || s.completed_at || s.started_at || '';
            let formattedTime = 'Recent';
            let fullTimeStr = rawTime;
            if (rawTime) {
                try {
                    const d = new Date(rawTime.replace(' ', 'T'));
                    if (!isNaN(d.getTime())) {
                        formattedTime = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
                        fullTimeStr = d.toLocaleString();
                    }
                } catch (e) {
                    formattedTime = rawTime.slice(11, 19) || rawTime;
                }
            }

            return `
                <div class="timeline-item ${isLatest ? 'timeline-item-latest' : ''}" 
                     data-scan-id="${s.id}" 
                     data-risk="${riskLevel}"
                     tabindex="0"
                     role="group"
                     aria-label="Scan #${s.id}: ${riskLevel.toUpperCase()}, ${entityLabel}, ${durText}">
                    <div class="timeline-item-header">
                        <span class="risk-dot ${riskDotClass}" title="${riskLevel.toUpperCase()} Risk" aria-hidden="true"></span>
                        <span class="timeline-scan-id font-mono">#${s.id}</span>
                        ${isLatest ? '<span class="badge badge-subtle badge-latest">LATEST</span>' : ''}
                    </div>
                    <div class="timeline-item-body">
                        <div class="timeline-time font-mono" title="${escapeHtml(fullTimeStr)}">${escapeHtml(formattedTime)}</div>
                        <div class="timeline-meta-row">
                            <span class="timeline-duration font-mono">${durText}</span>
                            <span class="timeline-bullet">•</span>
                            <span class="timeline-entities">${entityLabel}</span>
                        </div>
                    </div>

                    <!-- Hidden Data Payload for Floating Tooltip -->
                    <div class="timeline-tooltip-data" style="display:none;" aria-hidden="true">
                        <div class="sched-tooltip-header">
                            <span class="sched-tooltip-id font-mono">Scan #${s.id}</span>
                            ${riskBadge}
                        </div>
                        <div class="sched-tooltip-grid">
                            <div class="sched-tooltip-row">
                                <span class="sched-tooltip-k">Timestamp</span>
                                <span class="sched-tooltip-v font-mono">${escapeHtml(fullTimeStr)}</span>
                            </div>
                            <div class="sched-tooltip-row">
                                <span class="sched-tooltip-k">Duration</span>
                                <span class="sched-tooltip-v font-mono">${durMs.toFixed(1)} ms</span>
                            </div>
                            <div class="sched-tooltip-row">
                                <span class="sched-tooltip-k">Correlated Entities</span>
                                <span class="sched-tooltip-v font-bold">${entityCount}</span>
                            </div>
                            <div class="sched-tooltip-row">
                                <span class="sched-tooltip-k">High Risk Count</span>
                                <span class="sched-tooltip-v ${highCount > 0 ? 'text-danger font-bold' : ''}">${highCount}</span>
                            </div>
                        </div>
                        <div class="sched-tooltip-footer">Click to view snapshot →</div>
                    </div>
                </div>
            `;
        }).join('');

        // Next Scheduled Scan Marker (Reuse scheduler ETA logic)
        const nextMarkerHtml = `
            <div class="timeline-item timeline-item-next" id="timeline-item-next" role="status" aria-live="polite">
                <div class="timeline-item-header">
                    <span class="timeline-next-icon" aria-hidden="true">⏳</span>
                    <span class="timeline-scan-id">Next Scan</span>
                </div>
                <div class="timeline-item-body">
                    <div class="timeline-countdown font-mono font-bold" id="timeline-countdown-val">Calculating…</div>
                    <div class="timeline-meta-row">
                        <span class="timeline-schedule-status" id="timeline-schedule-status">Auto-scheduled</span>
                    </div>
                </div>
            </div>
        `;

        container.innerHTML = `
            <div class="timeline-track" role="list">
                ${itemsHtml}
                <div class="timeline-connector" aria-hidden="true"></div>
                ${nextMarkerHtml}
            </div>
        `;

        // Ensure floating tooltip element exists on timeline card (outside scroll container)
        const card = document.getElementById('timeline-card') || container.closest('.card') || container;
        let floatingTooltip = document.getElementById('timeline-floating-tooltip');
        if (!floatingTooltip) {
            floatingTooltip = document.createElement('div');
            floatingTooltip.id = 'timeline-floating-tooltip';
            floatingTooltip.className = 'sched-tooltip timeline-floating-tooltip';
            floatingTooltip.setAttribute('role', 'tooltip');
            card.appendChild(floatingTooltip);
        }

        const showFloatingTooltip = (item) => {
            const dataEl = item.querySelector('.timeline-tooltip-data');
            if (!dataEl || !floatingTooltip) return;

            floatingTooltip.innerHTML = dataEl.innerHTML;
            const cardRect = card.getBoundingClientRect();
            const itemRect = item.getBoundingClientRect();

            // Center horizontally over item relative to card
            const itemCenterInCard = itemRect.left - cardRect.left + (itemRect.width / 2);
            floatingTooltip.style.left = `${itemCenterInCard}px`;

            // Position above item: card's bottom minus item's top
            const bottomPos = cardRect.bottom - itemRect.top + 10;
            floatingTooltip.style.bottom = `${bottomPos}px`;

            // Edge clamping relative to card width
            floatingTooltip.classList.remove('clamped-left', 'clamped-right');
            const tooltipHalfWidth = 130;
            if (itemCenterInCard < tooltipHalfWidth) {
                floatingTooltip.style.left = `${tooltipHalfWidth}px`;
                floatingTooltip.classList.add('clamped-left');
            } else if (itemCenterInCard > cardRect.width - tooltipHalfWidth) {
                floatingTooltip.style.left = `${cardRect.width - tooltipHalfWidth}px`;
                floatingTooltip.classList.add('clamped-right');
            }

            floatingTooltip.style.opacity = '1';
            floatingTooltip.style.visibility = 'visible';
        };

        const hideFloatingTooltip = () => {
            if (!floatingTooltip) return;
            floatingTooltip.style.opacity = '0';
            floatingTooltip.style.visibility = 'hidden';
        };

        // Interactive hover and click listeners
        container.querySelectorAll('.timeline-item:not(.timeline-item-next)').forEach(item => {
            item.addEventListener('mouseenter', () => showFloatingTooltip(item));
            item.addEventListener('mouseleave', hideFloatingTooltip);
            item.addEventListener('focus', () => showFloatingTooltip(item));
            item.addEventListener('blur', hideFloatingTooltip);
            item.addEventListener('click', () => {
                const scanId = item.getAttribute('data-scan-id');
                if (scanId) {
                    window.location.href = `/history/${scanId}`;
                }
            });
            item.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    const scanId = item.getAttribute('data-scan-id');
                    if (scanId) {
                        window.location.href = `/history/${scanId}`;
                    }
                }
            });
        });

        // Hide floating tooltip when the timeline container scrolls horizontally
        container.addEventListener('scroll', hideFloatingTooltip, { passive: true });
    },

    updateEta(statusData) {
        const nextEl = document.getElementById(this.etaElementId);
        const countdownVal = document.getElementById('timeline-countdown-val');
        const nextMarker = document.getElementById('timeline-item-next');
        const schedStatus = document.getElementById('timeline-schedule-status');
        const intervalEl = document.getElementById(this.intervalElementId);

        if (!statusData || !statusData.scheduler) return;

        const isRunning = statusData.scheduler.is_running;
        const interval = statusData.scheduler.interval_seconds || 300;

        if (intervalEl) {
            intervalEl.textContent = isRunning ? `Every ${interval}s` : 'Disabled';
        }

        if (!isRunning) {
            this.nextScanMs = null;
            if (nextEl) nextEl.textContent = 'Scheduler: Standby';
            if (countdownVal) countdownVal.textContent = 'Standby';
            if (schedStatus) schedStatus.textContent = 'Scheduler stopped';
            if (nextMarker) nextMarker.classList.remove('is-overdue');
            return;
        }

        let lastScanMs = null;
        if (statusData.latest_scan && statusData.latest_scan.scan_time) {
            lastScanMs = new Date(statusData.latest_scan.scan_time.replace(' ', 'T')).getTime();
        } else if (statusData.scheduler.last_scan_time) {
            lastScanMs = statusData.scheduler.last_scan_time * 1000;
        }

        if (!lastScanMs) {
            this.nextScanMs = Date.now() + interval * 1000;
        } else {
            this.nextScanMs = lastScanMs + interval * 1000;
        }

        this.tickCountdown();
    },

    tickCountdown() {
        const nextEl = document.getElementById(this.etaElementId);
        const countdownVal = document.getElementById('timeline-countdown-val');
        const nextMarker = document.getElementById('timeline-item-next');

        if (!this.nextScanMs) return;

        const remaining = Math.round((this.nextScanMs - Date.now()) / 1000);
        if (remaining <= 0) {
            this.isOverdue = true;
            if (nextEl) {
                nextEl.textContent = 'Scan Overdue';
                nextEl.className = 'sched-timeline-next text-warning';
            }
            if (countdownVal) {
                countdownVal.textContent = 'Overdue';
            }
            if (nextMarker) {
                nextMarker.classList.add('is-overdue');
            }
        } else {
            this.isOverdue = false;
            const durStr = formatDuration(remaining);
            if (nextEl) {
                nextEl.textContent = `Next in: ${durStr}`;
                nextEl.className = 'sched-timeline-next';
            }
            if (countdownVal) {
                countdownVal.textContent = `in ${durStr}`;
            }
            if (nextMarker) {
                nextMarker.classList.remove('is-overdue');
            }
        }
    },

    startCountdownTicker() {
        if (this.countdownTimerId) return;
        this.countdownTimerId = setInterval(() => {
            this.tickCountdown();
        }, 1000);
    },

    startAutoRefresh() {
        if (this.timerId) return;
        this.timerId = setInterval(() => {
            this.load();
        }, this.refreshIntervalMs);
    }
};

window.TimelineCard = TimelineCard;
window.loadSchedulerTimeline = () => TimelineCard.load();

/**
 * SignalWaterfall — Per-Entity 3-Signal Expandable Visualization
 * Manages accordion expand/collapse, signal score contribution calculation,
 * severity classifications, and keyboard accessibility.
 */
class SignalWaterfall {
    static WEIGHTS = {
        process_view: 0.40,
        persistence: 0.30,
        signature: 0.30
    };

    static LABELS = {
        process_view: 'Process Views',
        persistence: 'Persistence',
        signature: 'Signature'
    };

    static _initialized = false;

    static classifySeverity(score) {
        if (score >= 0.60) return 'HIGH';
        if (score >= 0.40) return 'MEDIUM';
        return 'LOW';
    }

    static getRiskDotClass(severity) {
        const s = (severity || '').toUpperCase();
        if (s === 'HIGH') return 'risk-dot-high';
        if (s === 'MEDIUM') return 'risk-dot-medium';
        if (s === 'LOW') return 'risk-dot-low';
        return 'risk-dot-inactive';
    }

    static getFillClass(severity) {
        const s = (severity || '').toUpperCase();
        if (s === 'HIGH') return 'fill-high severity-high';
        if (s === 'MEDIUM') return 'fill-medium severity-medium';
        if (s === 'LOW') return 'fill-low severity-low';
        return 'fill-inactive';
    }

    static init() {
        const table = document.getElementById('entities-table');
        if (!table || this._initialized) return;
        this._initialized = true;

        // Click delegation on entity rows
        table.addEventListener('click', (e) => {
            if (e.target.closest('a, .btn:not(.waterfall-chevron-btn)')) {
                return;
            }

            const row = e.target.closest('.entity-row');
            if (row) {
                this.toggle(row);
            }
        });

        // Keyboard navigation: Enter/Space to toggle, Escape to close
        table.addEventListener('keydown', (e) => {
            const row = e.target.closest('.entity-row');
            if (row && (e.key === 'Enter' || e.key === ' ')) {
                e.preventDefault();
                this.toggle(row);
            } else if (e.key === 'Escape') {
                this.closeAll();
            }
        });

        // Global Escape key to close any open waterfall
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                this.closeAll();
            }
        });
    }

    static toggle(rowOrIndex) {
        const row = typeof rowOrIndex === 'string' || typeof rowOrIndex === 'number'
            ? document.querySelector(`.entity-row[data-index="${rowOrIndex}"]`) || document.getElementById(`entity-row-${rowOrIndex}`)
            : rowOrIndex;

        if (!row) return;

        const isExpanded = row.classList.contains('is-expanded') || row.getAttribute('aria-expanded') === 'true';
        if (isExpanded) {
            this.collapse(row);
        } else {
            this.expand(row);
        }
    }

    static expand(row) {
        this.closeAll();

        let waterfallRow = row.nextElementSibling && row.nextElementSibling.classList.contains('waterfall-row')
            ? row.nextElementSibling
            : document.getElementById(row.getAttribute('aria-controls')?.replace('waterfall-panel-', 'waterfall-row-'));

        if (!waterfallRow) {
            // Create waterfall sub-row dynamically on demand
            const index = row.getAttribute('data-index') || Math.random().toString(36).substring(2, 9);
            const panelId = `waterfall-panel-${index}`;
            waterfallRow = document.createElement('tr');
            waterfallRow.className = 'waterfall-row hidden';
            waterfallRow.id = `waterfall-row-${index}`;
            waterfallRow.setAttribute('aria-hidden', 'true');

            const procName = row.getAttribute('data-process-name') || row.querySelector('.font-bold')?.textContent.trim() || 'Process';
            const td = document.createElement('td');
            td.colSpan = 7;
            td.className = 'waterfall-cell';

            const entityData = {
                process_name: procName,
                score: parseFloat(row.getAttribute('data-score')) || 0.0,
                risk_level: row.getAttribute('data-severity') || 'LOW',
                signals_triggered: row.getAttribute('data-signals') || ''
            };

            td.innerHTML = `
                <div class="waterfall-panel" id="${panelId}" role="region" aria-label="Signal breakdown for ${escapeHtml(procName)}">
                    ${this.renderPanel(entityData)}
                </div>
            `;
            waterfallRow.appendChild(td);
            row.setAttribute('aria-controls', panelId);
            row.parentNode.insertBefore(waterfallRow, row.nextSibling);
        }

        row.classList.add('is-expanded');
        row.setAttribute('aria-expanded', 'true');

        waterfallRow.classList.remove('hidden');
        waterfallRow.setAttribute('aria-hidden', 'false');

        // Force browser layout reflow before adding .is-expanded for smooth CSS transition
        void waterfallRow.offsetHeight;
        waterfallRow.classList.add('is-expanded');
    }

    static collapse(row) {
        const waterfallRow = row.nextElementSibling && row.nextElementSibling.classList.contains('waterfall-row')
            ? row.nextElementSibling
            : document.getElementById(row.getAttribute('aria-controls')?.replace('waterfall-panel-', 'waterfall-row-'));

        row.classList.remove('is-expanded');
        row.setAttribute('aria-expanded', 'false');

        if (!waterfallRow) return;

        waterfallRow.classList.remove('is-expanded');
        waterfallRow.setAttribute('aria-hidden', 'true');

        const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
        if (prefersReducedMotion) {
            waterfallRow.classList.add('hidden');
        } else {
            setTimeout(() => {
                if (!waterfallRow.classList.contains('is-expanded')) {
                    waterfallRow.classList.add('hidden');
                }
            }, 300);
        }
    }

    static closeAll() {
        const expandedRows = document.querySelectorAll('.entity-row.is-expanded');
        expandedRows.forEach(row => this.collapse(row));
    }

    static renderPanel(entity) {
        const signals = (entity.signals_triggered || '').split(',').map(s => s.trim().toLowerCase());
        const totalScore = parseFloat(entity.score) || 0.0;
        const entitySev = entity.risk_level || this.classifySeverity(totalScore);

        const itemsHtml = Object.entries(this.WEIGHTS).map(([key, weight]) => {
            const isActive = signals.includes(key);
            const label = this.LABELS[key] || key;
            const rawScore = isActive ? 1.0 : 0.0;
            const contrib = isActive ? weight : 0.0;
            const percent = isActive ? Math.round(weight * 100) : 0;
            const sev = isActive ? (weight >= 0.40 ? 'HIGH' : 'MEDIUM') : 'LOW';
            const dotClass = isActive ? (weight >= 0.40 ? 'risk-dot-high' : 'risk-dot-medium') : 'risk-dot-inactive';
            const fillClass = isActive ? (weight >= 0.40 ? 'fill-high severity-high' : 'fill-medium severity-medium') : 'fill-inactive';
            const contribClass = isActive ? (weight >= 0.40 ? 'text-danger font-bold' : 'text-warning font-bold') : 'text-tertiary';

            return `
                <div class="waterfall-signal-item ${isActive ? 'is-active' : ''}" data-signal-name="${escapeHtml(key)}">
                    <div class="signal-label-col">
                        <span class="signal-status-dot ${dotClass}"></span>
                        <span class="signal-label">${escapeHtml(label)}</span>
                        <span class="signal-weight text-tertiary font-mono">(weight ${weight.toFixed(2)})</span>
                    </div>
                    <div class="signal-bar-col">
                        <div class="signal-bar" role="progressbar" aria-valuenow="${contrib.toFixed(2)}" aria-valuemin="0" aria-valuemax="1" aria-label="${escapeHtml(label)} contribution">
                            <div class="signal-bar-fill ${fillClass}" style="width: ${percent}%;"></div>
                        </div>
                    </div>
                    <div class="signal-values-col font-mono">
                        <span class="signal-raw">Raw: <strong>${rawScore.toFixed(2)}</strong></span>
                        <span class="signal-contrib ${contribClass}">Contrib: <strong>+${contrib.toFixed(2)}</strong></span>
                    </div>
                </div>
            `;
        }).join('');

        return `
            <div class="waterfall-header">
                <div class="waterfall-header-title">
                    <span class="waterfall-title-text font-mono">SIGNAL RISK BREAKDOWN</span>
                    <span class="waterfall-formula text-tertiary font-mono">Composite = min(1.0, &Sigma; active weights)</span>
                </div>
                <div class="waterfall-composite-pill font-mono">
                    <span class="text-tertiary">Entity Risk:</span>
                    <span class="waterfall-composite-score font-bold font-mono">${totalScore.toFixed(2)}</span>
                    <span class="badge badge-severity badge-${entitySev.toLowerCase()}">${escapeHtml(entitySev)}</span>
                </div>
            </div>
            <div class="waterfall-signals-grid">
                ${itemsHtml}
            </div>
        `;
    }
}

window.SignalWaterfall = SignalWaterfall;

/**
 * BaselineVisualDiff — Side-by-Side Candidate vs Current State Comparison Modal
 * Fetches live enumeration and candidate records, renders visual highlights for
 * Added (green), Removed (red), and Modified (yellow) entries, and handles baseline acceptance.
 */
class BaselineVisualDiff {
    static currentCategory = null;

    static async openDiff(category) {
        this.currentCategory = category;
        const modal = document.getElementById('baseline-diff-modal');
        if (!modal) return;

        const catTitle = document.getElementById('diff-modal-category');
        if (catTitle) catTitle.textContent = (category || '').toUpperCase();

        // Update active category tab
        const normCat = (category || 'registry').toLowerCase().replace(/s$/, '');
        document.querySelectorAll('.diff-tab-btn').forEach(btn => {
            btn.classList.remove('btn-primary', 'active');
            btn.classList.add('btn-secondary');
        });
        const activeTab = document.getElementById(`diff-tab-${normCat}`);
        if (activeTab) {
            activeTab.classList.remove('btn-secondary');
            activeTab.classList.add('btn-primary', 'active');
        }

        const loading = document.getElementById('diff-loading');
        const errorEl = document.getElementById('diff-error');
        const panel = document.getElementById('diff-panel-container');
        const summary = document.getElementById('diff-summary-badges');

        if (loading) loading.style.display = 'block';
        if (errorEl) errorEl.style.display = 'none';
        if (panel) panel.style.display = 'none';
        if (summary) summary.innerHTML = '';

        modal.classList.remove('hidden');
        document.body.style.overflow = 'hidden';

        try {
            const resp = await fetch(`/api/baseline/compare?category=${encodeURIComponent(category)}`);
            if (!resp.ok) {
                const errData = await resp.json().catch(() => ({}));
                throw new Error(errData.message || `HTTP ${resp.status}`);
            }
            const data = await resp.json();
            this.renderDiff(data);
        } catch (err) {
            if (loading) loading.style.display = 'none';
            if (errorEl) {
                errorEl.style.display = 'block';
                const msg = document.getElementById('diff-error-msg');
                if (msg) msg.textContent = `Failed to compute baseline comparison: ${err.message}`;
            }
        }
    }

    static closeModal() {
        const modal = document.getElementById('baseline-diff-modal');
        if (modal) modal.classList.add('hidden');
        document.body.style.overflow = '';
        this.currentCategory = null;
    }

    static async acceptCurrentCategory() {
        if (!this.currentCategory) return;
        const btn = document.getElementById('btn-accept-diff-baseline');
        const oldText = btn ? btn.textContent : '';
        if (btn) {
            btn.disabled = true;
            btn.textContent = 'Accepting…';
        }

        try {
            const csrfToken = getCsrfToken();
            const resp = await fetch('/api/baseline/accept', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken
                },
                body: JSON.stringify({ category: this.currentCategory })
            });

            const data = await resp.json();
            if (resp.ok && data.success) {
                showToast(`Baseline for ${this.currentCategory.toUpperCase()} accepted successfully!`, 'success');
                this.closeModal();
                setTimeout(() => window.location.reload(), 800);
            } else {
                showToast(`Acceptance failed: ${data.message || 'Unknown error'}`, 'error');
                if (btn) {
                    btn.disabled = false;
                    btn.textContent = oldText;
                }
            }
        } catch (err) {
            showToast(`Error accepting baseline: ${err.message}`, 'error');
            if (btn) {
                btn.disabled = false;
                btn.textContent = oldText;
            }
        }
    }

    static renderDiff(data) {
        const loading = document.getElementById('diff-loading');
        const panel = document.getElementById('diff-panel-container');
        if (loading) loading.style.display = 'none';
        if (panel) panel.style.display = 'grid';

        const diff = data.diff || { added: [], removed: [], modified: [], unchanged: [] };
        const counts = data.counts || {};
        const cat = data.category || 'item';

        // Render summary badges in header
        const summary = document.getElementById('diff-summary-badges');
        if (summary) {
            summary.innerHTML = `
                <span class="badge badge-diff-added font-mono">+${diff.added.length} Added</span>
                <span class="badge badge-diff-removed font-mono">-${diff.removed.length} Removed</span>
                <span class="badge badge-diff-modified font-mono">~${diff.modified.length} Modified</span>
                <span class="badge badge-secondary font-mono">${diff.unchanged.length} Unchanged</span>
            `;
        }

        const currCount = document.getElementById('diff-current-count');
        if (currCount) currCount.textContent = `${counts.current || 0} entries`;

        const candCount = document.getElementById('diff-candidate-count');
        if (candCount) candCount.textContent = `${counts.candidate || 0} entries`;

        // Left: Current System State
        const leftList = document.getElementById('diff-current-list');
        if (leftList) {
            const currentItems = [];

            // 1. Removed entries (in current, not in candidate)
            diff.removed.forEach(item => {
                currentItems.push({
                    key: item.entry_key,
                    value: item.entry_value,
                    status: 'removed',
                    badge: 'REMOVED (CURRENT ONLY)',
                    badgeClass: 'badge-diff-removed'
                });
            });

            // 2. Modified entries in current
            diff.modified.forEach(item => {
                currentItems.push({
                    key: item.entry_key,
                    value: item.current_value,
                    status: 'modified',
                    badge: 'MODIFIED (LIVE VALUE)',
                    badgeClass: 'badge-diff-modified'
                });
            });

            // 3. Unchanged entries
            diff.unchanged.forEach(item => {
                currentItems.push({
                    key: item.entry_key,
                    value: item.entry_value,
                    status: 'unchanged',
                    badge: 'UNCHANGED',
                    badgeClass: 'badge-secondary'
                });
            });

            leftList.innerHTML = currentItems.length > 0
                ? currentItems.map(item => this._renderEntryCard(item, cat)).join('')
                : '<div class="diff-empty-state text-tertiary font-mono">No entries enumerated in current live state.</div>';
        }

        // Right: Proposed Baseline (Candidate)
        const rightList = document.getElementById('diff-candidate-list');
        if (rightList) {
            const candidateItems = [];

            // 1. Added entries (in candidate, not in current)
            diff.added.forEach(item => {
                candidateItems.push({
                    key: item.entry_key,
                    value: item.entry_value,
                    status: 'added',
                    badge: 'ADDED (PROPOSED)',
                    badgeClass: 'badge-diff-added'
                });
            });

            // 2. Modified entries in candidate
            diff.modified.forEach(item => {
                candidateItems.push({
                    key: item.entry_key,
                    value: item.candidate_value,
                    status: 'modified',
                    badge: 'MODIFIED (PROPOSED VALUE)',
                    badgeClass: 'badge-diff-modified'
                });
            });

            // 3. Unchanged entries
            diff.unchanged.forEach(item => {
                candidateItems.push({
                    key: item.entry_key,
                    value: item.entry_value,
                    status: 'unchanged',
                    badge: 'UNCHANGED',
                    badgeClass: 'badge-secondary'
                });
            });

            rightList.innerHTML = candidateItems.length > 0
                ? candidateItems.map(item => this._renderEntryCard(item, cat)).join('')
                : '<div class="diff-empty-state text-tertiary font-mono">No candidate entries found in database.</div>';
        }
    }

    static _renderEntryCard(item, category) {
        return `
            <div class="diff-entry ${item.status}">
                <div class="diff-entry-header">
                    <span class="badge badge-entity-type">${escapeHtml(category || 'item')}</span>
                    <span class="diff-entry-key font-mono font-bold" title="${escapeHtml(item.key)}">${escapeHtml(item.key)}</span>
                    <span class="badge ${item.badgeClass} font-mono">${escapeHtml(item.badge)}</span>
                </div>
                ${item.value ? `
                    <div class="diff-entry-value font-mono text-tertiary" title="${escapeHtml(item.value)}">
                        <span class="text-subtle">Value:</span> ${escapeHtml(item.value)}
                    </div>
                ` : ''}
            </div>
        `;
    }
}

window.BaselineVisualDiff = BaselineVisualDiff;
