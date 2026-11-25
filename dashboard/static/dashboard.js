/**
 * GhostHunt — Dashboard Client Script
 * Implements 5s asynchronous polling, manual scan trigger, HTTP 409 conflict handling,
 * live entity search & severity filtering, and baseline review & reset actions with CSRF protection.
 * Day 1 UI Polish: Scheduler ETA countdown, Skeleton loaders, Enhanced toast system with actions & persistence.
 */

let currentSeverityFilter = 'ALL';
let schedulerIntervalId = null;
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

        if (matchesSeverity && matchesSearch) {
            row.style.display = '';
            visibleCount++;
        } else {
            row.style.display = 'none';
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

// Trigger manual scan cycle
async function triggerManualScan() {
    const btn = document.getElementById('btn-manual-scan');
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<span class="spin">⟳</span> <span>Scanning...</span>';
    }

    try {
        const response = await fetch('/api/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': getCsrfToken(),
            },
            body: JSON.stringify({}),
        });

        const data = await response.json();

        if (response.status === 409) {
            // Concurrency Guard Conflict
            showToast(data.message || 'Another protected operation is currently active.', 'warning');
        } else if (response.ok && data.success) {
            showToast(`Scan #${data.scan_id} completed successfully in ${data.duration_ms.toFixed(1)} ms!`, 'success');
            setTimeout(() => window.location.reload(), 1200);
        } else {
            showToast(data.message || 'Scan execution failed.', 'danger');
        }
    } catch (err) {
        showToast(`Network or server error: ${err.message}`, 'danger');
    } finally {
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
            showToast('Another protected operation is in progress. Please wait.', 'warning');
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
            showToast('Another operation is in progress. Reset aborted.', 'warning');
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
    if (!tbody) return;
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
    container.innerHTML = '';
    for (let i = 0; i < count; i++) {
        const div = document.createElement('div');
        div.className = 'skeleton-card';
        container.appendChild(div);
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

// Update scheduler ETA countdown
function updateSchedulerEta(data) {
    const etaEl = document.getElementById('scheduler-eta');
    if (!etaEl) return;

    if (!data.scheduler || !data.scheduler.is_running) {
        etaEl.textContent = 'Next scan: —';
        etaEl.style.display = 'none';
        return;
    }

    const interval = data.scheduler.interval_seconds || 300;

    // Use latest completed scan time (most accurate)
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

    const nowMs = Date.now();
    const elapsed = Math.floor((nowMs - lastScanMs) / 1000);
    const remaining = Math.max(0, interval - elapsed);

    if (remaining <= 0) {
        // Show time since last scan when overdue
        const overdue = Math.abs(remaining);
        etaEl.textContent = `Overdue by ${formatDuration(overdue)}`;
        etaEl.classList.add('text-warning');
    } else {
        etaEl.textContent = `Next scan in: ${formatDuration(remaining)}`;
        etaEl.classList.remove('text-warning');
    }
    etaEl.style.display = 'inline-flex';
}

// Asynchronous 5-Second Status Poller (FR-6.6)
let lastKnownScanId = null;

async function pollStatus() {
    try {
        const response = await fetch('/api/status');
        if (!response.ok) return;

        const data = await response.json();

        // Update scheduler status indicator
        const schedIndicator = document.getElementById('scheduler-indicator');
        if (schedIndicator && data.scheduler) {
            if (data.scheduler.is_running) {
                schedIndicator.className = 'scheduler-badge running';
                schedIndicator.querySelector('.label').textContent = 'Scheduler: ACTIVE';
            } else {
                schedIndicator.className = 'scheduler-badge idle';
                schedIndicator.querySelector('.label').textContent = 'Scheduler: STANDBY';
            }
        }

        // Update scheduler ETA countdown
        updateSchedulerEta(data);

        // Detect new completed scan on main dashboard page
        if (data.latest_completed_scan_id !== undefined && data.latest_completed_scan_id !== null) {
            if (lastKnownScanId === null) {
                lastKnownScanId = data.latest_completed_scan_id;
            } else if (data.latest_completed_scan_id > lastKnownScanId) {
                lastKnownScanId = data.latest_completed_scan_id;
                showToast(`New scan #${data.latest_completed_scan_id} completed. Updating view...`, 'info', 2000);
                if (window.location.pathname === '/') {
                    setTimeout(() => window.location.reload(), 1500);
                }
            }
        }
    } catch (e) {
        // Silent polling failure to avoid annoying user during transient server restart
    }
}

// Start 5s interval and keyboard shortcuts on DOM load
document.addEventListener('DOMContentLoaded', () => {
    loadToastHistory();

    // Show skeleton loaders on initial load for main dashboard
    if (window.location.pathname === '/') {
        showTableSkeleton('entities-table', 5, 7);
        showCardSkeleton('.metrics-grid', 4);
    }

    pollStatus();
    schedulerIntervalId = setInterval(pollStatus, 5000);

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            closeResetModal();
        }
    });

    // Clean up skeleton loaders after first successful poll
    setTimeout(() => {
        removeSkeletons('entities-table', '.metrics-grid');
    }, 6000);
});