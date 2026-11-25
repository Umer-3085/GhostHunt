/**
 * GhostHunt — Dashboard Client Script
 * Implements 5s asynchronous polling, manual scan trigger, HTTP 409 conflict handling,
 * live entity search & severity filtering, and baseline review & reset actions with CSRF protection.
 */

let currentSeverityFilter = 'ALL';

// Retrieve CSRF token from page meta tag
function getCsrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute('content') : '';
}

// Toast notification helper
function showToast(message, type = 'info', durationMs = 4000) {
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
    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(100%)';
        toast.style.transition = 'all 0.3s ease';
        setTimeout(() => toast.remove(), 300);
    }, durationMs);
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
            showToast(`Baseline for ${category || 'all categories'} accepted as trusted reference.`, 'success');
            setTimeout(() => window.location.reload(), 1200);
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
            showToast('Baselines reset successfully to NOT_INITIALIZED.', 'success');
            setTimeout(() => window.location.reload(), 1200);
        } else {
            showToast(data.message || 'Baseline reset failed.', 'danger');
        }
    } catch (err) {
        showToast(`Reset error: ${err.message}`, 'danger');
    }
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
    pollStatus();
    setInterval(pollStatus, 5000);

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            closeResetModal();
        }
    });
});
