let cachedHistory = [];
let cveChartInstance = null;
let notifications = [];
const API_BASE = 'https://apkrack.locamartin.workers.dev';
const SESSION_TOKEN_KEY = 'WORKSPACE_SESSION_TOKEN';

function getSessionToken() {
    return sessionStorage.getItem(SESSION_TOKEN_KEY);
}

async function submitLogin(event) {
    event.preventDefault();
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const error = document.getElementById('login-error');
    const submit = document.getElementById('login-submit');

    error.textContent = '';
    submit.disabled = true;
    submit.querySelector('span').textContent = 'Signing in…';
    try {
        const response = await fetch(`${API_BASE}/api/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        const result = await response.json().catch(() => ({}));
        if (!response.ok) {
            const message = result.error === 'username_invalid'
                ? 'Username is incorrect.'
                : result.error === 'password_invalid'
                    ? 'Password is incorrect.'
                    : result.error === 'password_verifier_invalid'
                        ? 'Password verifier configuration is invalid.'
                    : 'Unable to sign in. Please try again.';
            throw new Error(message);
        }
        if (!result.token) throw new Error('Unable to start a session.');
        sessionStorage.setItem(SESSION_TOKEN_KEY, result.token);
        document.getElementById('password').value = '';
        addNotification('Session started.');
        checkAuthentication();
    } catch (err) {
        error.textContent = err.message || 'Unable to sign in.';
    } finally {
        submit.disabled = false;
        submit.querySelector('span').textContent = 'Continue';
    }
}

/**
 * Enforces mandatory login screen before displaying dashboard
 */
function checkAuthentication() {
    const token = getSessionToken();
    const overlay = document.getElementById("login-overlay");
    const app = document.getElementById("dashboard-app");

    if (token) {
        if (overlay) overlay.style.display = "none";
        if (app) app.style.display = "block";
        fetchStatus();
    } else {
        if (overlay) overlay.style.display = "flex";
        if (app) app.style.display = "none";
    }
}

function logoutSession() {
    sessionStorage.removeItem(SESSION_TOKEN_KEY);
    sessionStorage.removeItem("REPORT_ENCRYPTION_KEY");
    window.location.reload();
}

/**
 * Key Utility Helpers
 */
function updateKeyIndicator() {
    const hasKey = !!sessionStorage.getItem("REPORT_ENCRYPTION_KEY");
    const indicator = document.getElementById("key-indicator");
    if (indicator) {
        indicator.innerText = hasKey ? "Key: Active" : "Key: Unset";
        indicator.style.color = hasKey ? "#22c55e" : "#94a3b8";
    }
}

function setEncryptionKey() {
    const key = prompt("Enter Report Decryption Key:");
    if (key) {
        sessionStorage.setItem("REPORT_ENCRYPTION_KEY", key);
        updateKeyIndicator();
        fetchStatus();
    }
}

function clearKey() {
    sessionStorage.removeItem("REPORT_ENCRYPTION_KEY");
    updateKeyIndicator();
}

function getDecryptionKey() {
    let key = sessionStorage.getItem("REPORT_ENCRYPTION_KEY");
    if (!key) {
        key = prompt("Enter Decryption Key:");
        if (key) {
            sessionStorage.setItem("REPORT_ENCRYPTION_KEY", key);
            updateKeyIndicator();
        }
    }
    return key;
}

function formatAppName(pkg) {
    if (!pkg) return "Unknown";
    const segments = pkg.split('.').filter(s => !['com', 'org', 'net', 'io', 'ch', 'nl', 'gp', 'twa'].includes(s.toLowerCase()));
    const targetSegment = segments.length > 0 ? segments[0] : pkg.split('.').pop();
    return targetSegment.charAt(0).toUpperCase() + targetSegment.slice(1);
}

function addNotification(msg) {
    const timestamp = new Date().toLocaleTimeString();
    notifications.unshift(`[${timestamp}] ${msg}`);
    const badge = document.getElementById("notif-badge");
    const list = document.getElementById("notif-list");
    
    if (badge) {
        badge.textContent = notifications.length;
        badge.style.display = notifications.length > 0 ? "inline-block" : "none";
    }
    if (list) {
        list.innerHTML = notifications.map(n => `<li style="padding:4px 0; border-bottom:1px solid rgba(255,255,255,0.05);">${n}</li>`).join("");
    }
}

function toggleNotifications() {
    const dropdown = document.getElementById("notif-dropdown");
    if (dropdown) {
        dropdown.style.display = dropdown.style.display === "none" ? "block" : "none";
    }
}

async function fetchStatus() {
    const passKey = sessionStorage.getItem('REPORT_ENCRYPTION_KEY');
    if (!passKey) {
        cachedHistory = [];
        renderTable();
        return;
    }
    try {
        const response = await fetch(`${API_BASE}/api/status`, {
            headers: { Authorization: `Bearer ${getSessionToken()}` },
            cache: 'no-store'
        });
        if (!response.ok) throw new Error(`Status request failed (${response.status}).`);
        const data = JSON.parse(await decryptRawPayload(await response.text(), passKey));

        const stateBadge = document.getElementById('state');
        if (stateBadge) {
            const statusText = data.status || 'Idle';
            stateBadge.textContent = statusText;
            stateBadge.className = `badge ${statusText === 'Analyzing' ? 'badge-analyzing' : 'badge-idle'}`;
        }

        const currentAppEl = document.getElementById('current-app');
        if (currentAppEl) currentAppEl.textContent = data.current_app || 'None';

        const progressEl = document.getElementById('progress');
        if (progressEl) progressEl.textContent = `${data.completed || 0} / ${data.total || 0}`;

        cachedHistory = Array.isArray(data.history) ? data.history : [];
        updateRiskMetrics();
        renderTable();
        updateCveChart();
    } catch (e) {
        console.error("Dashboard polling error:", e);
        if (e.message.includes('401') || e.message.includes('403')) logoutSession();
    }
}

function updateRiskMetrics() {
    let elevated = 0;
    let moderate = 0;
    cachedHistory.forEach(item => {
        const summary = item.cve_summary || {};
        elevated += (summary.critical || 0) + (summary.high || 0);
        moderate += summary.medium || 0;
    });
    const elevatedEl = document.getElementById('elevated-risks');
    const moderateEl = document.getElementById('moderate-risks');
    if (elevatedEl) elevatedEl.textContent = elevated;
    if (moderateEl) moderateEl.textContent = moderate;
}

function renderTable() {
    const list = document.getElementById('completed-apps');
    if (!list) return;

    list.innerHTML = '';
    const searchInput = document.getElementById('search');
    const query = (searchInput ? searchInput.value : '').toLowerCase().trim();

    const filtered = cachedHistory.filter(item => {
        const name = item.app_name || formatAppName(item.package);
        return !query || 
            (item.package && item.package.toLowerCase().includes(query)) ||
            (name && name.toLowerCase().includes(query));
    });

    if (filtered.length === 0) {
        list.innerHTML = `<tr><td colspan="5" style="text-align:center; color: var(--text-muted);">No records found.</td></tr>`;
        return;
    }

    filtered.forEach((item, index) => {
        const row = document.createElement('tr');
        const appName = item.app_name || formatAppName(item.package);

        row.innerHTML = `
            <td style="color: var(--text-muted); text-align: center;">${index + 1}</td>
            <td style="font-weight: 600; color: var(--text-main);">${appName}</td>
            <td><code>${item.package}</code></td>
            <td style="color: var(--text-muted);">${item.timestamp}</td>
            <td>
                <div class="report-actions">
                    <button class="report-btn" onclick="viewReport('${item.report_id}', '${item.package}', 'secrets.txt.enc')">Secrets</button>
                    <button class="report-btn" onclick="viewReport('${item.report_id}', '${item.package}', 'mobsfscan.json.enc')">Static Recon</button>
                    <button class="report-btn cve" onclick="viewReport('${item.report_id}', '${item.package}', 'cve.json.enc')">Trivy CVE</button>
                </div>
            </td>
        `;
        list.appendChild(row);
    });

    if (window.lucide) {
        lucide.createIcons();
    }
}

function updateCveChart() {
    const labels = [];
    const highCounts = [];
    const mediumCounts = [];
    const lowCounts = [];

    if (cachedHistory.length > 0) {
        cachedHistory.forEach(item => {
            labels.push(item.package);
            const summary = item.cve_summary || { critical: 0, high: 0, medium: 0, low: 0 };
            highCounts.push((summary.critical || 0) + (summary.high || 0));
            mediumCounts.push(summary.medium || 0);
            lowCounts.push(summary.low || 0);
        });
    }

    renderChartJS(labels, highCounts, mediumCounts, lowCounts);
}

function renderChartJS(labels = [], high = [], medium = [], low = []) {
    const chartCanvas = document.getElementById('cveChart');
    if (!chartCanvas) return;

    const ctx = chartCanvas.getContext('2d');
    if (cveChartInstance) cveChartInstance.destroy();

    cveChartInstance = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels.length > 0 ? labels : ['No Data'],
            datasets: [
                { label: 'High / Critical', data: high, backgroundColor: '#ef4444', borderRadius: 4 },
                { label: 'Medium', data: medium, backgroundColor: '#f59e0b', borderRadius: 4 },
                { label: 'Low', data: low, backgroundColor: '#38bdf8', borderRadius: 4 }
            ]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: { stacked: true, grid: { color: 'rgba(51, 65, 85, 0.6)' }, ticks: { color: '#94a3b8' } },
                y: { stacked: true, grid: { display: false }, ticks: { color: '#f8fafc' } }
            },
            plugins: {
                legend: { position: 'top', labels: { color: '#f8fafc' } }
            }
        }
    });
}

async function viewReport(reportId, packageName, fileName) {
    const modal = document.getElementById('reportModal');
    const modalTitle = document.getElementById('modalTitle');
    const modalBody = document.getElementById('modalBody');

    if (!modal || !modalTitle || !modalBody) return;

    const passKey = getDecryptionKey();
    if (!passKey) {
        alert("Decryption passphrase is required to view encrypted reports.");
        return;
    }

    modalTitle.textContent = `${packageName} — ${fileName.replace('.enc', '')}`;
    modalBody.textContent = "Authenticating & Fetching report payload...";
    modal.style.display = "block";

    try {
        if (!reportId) throw new Error('This protected report needs to be migrated by the pipeline.');
        const workerUrl = `${API_BASE}/api/report?id=${encodeURIComponent(reportId)}&file=${encodeURIComponent(fileName)}`;
        const headers = { Authorization: `Bearer ${getSessionToken()}` };

        const response = await fetch(workerUrl, { headers });

        if (!response.ok) {
            const errText = await response.text();
            throw new Error(`Worker Error (${response.status}): ${errText}`);
        }

        const encryptedBase64 = await response.text();
        modalBody.textContent = "Decrypting payload client-side...";

        const decryptedText = await decryptRawPayload(encryptedBase64, passKey);

        try {
            const parsedJson = JSON.parse(decryptedText);
            modalBody.textContent = JSON.stringify(parsedJson, null, 2);
        } catch (e) {
            modalBody.textContent = decryptedText;
        }
    } catch (err) {
        modalBody.textContent = err.message || "Decryption failed or access denied.";
    }
}

function closeModal() {
    const modal = document.getElementById('reportModal');
    if (modal) modal.style.display = "none";
}

document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('login-form').addEventListener('submit', submitLogin);
    checkAuthentication();
    updateKeyIndicator();
    if (window.lucide) {
        lucide.createIcons();
    }
    setInterval(() => {
        if (getSessionToken()) {
            fetchStatus();
        }
    }, 5000); 
});
