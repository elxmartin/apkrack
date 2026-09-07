let cachedHistory = [];
let cveChartInstance = null;
let notifications = [];

/**
 * Handle Google OAuth Callback Response & Gatekeeper
 */
function handleCredentialResponse(response) {
    if (response && response.credential) {
        sessionStorage.setItem("GOOGLE_ID_TOKEN", response.credential);
        addNotification("Google Authentication Successful.");
        checkAuthentication();
    }
}

/**
 * Enforces mandatory login screen before displaying dashboard
 */
function checkAuthentication() {
    const token = sessionStorage.getItem("GOOGLE_ID_TOKEN");
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
    sessionStorage.removeItem("GOOGLE_ID_TOKEN");
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
    try {
        const response = await fetch('./status.json?t=' + Date.now(), { cache: 'no-store' });
        const data = await response.json();

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
        renderTable();
        updateCveChart();
    } catch (e) {
        console.error("Dashboard polling error:", e);
    }
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
                    <button class="report-btn" onclick="viewReport('${item.package}', 'secrets.txt.enc')">Secrets</button>
                    <button class="report-btn" onclick="viewReport('${item.package}', 'mobsfscan.json.enc')">Static Recon</button>
                    <button class="report-btn cve" onclick="viewReport('${item.package}', 'cve.json.enc')">Trivy CVE</button>
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

async function viewReport(packageName, fileName) {
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
        const googleToken = sessionStorage.getItem("GOOGLE_ID_TOKEN");
        const workerUrl = `https://apkrack.locamartin.workers.dev/api/report?package=${encodeURIComponent(packageName)}&file=${encodeURIComponent(fileName)}`;
        
        const headers = {};
        if (googleToken) {
            headers["Authorization"] = `Bearer ${googleToken}`;
        }

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
    checkAuthentication();
    updateKeyIndicator();
    if (window.lucide) {
        lucide.createIcons();
    }
    setInterval(() => {
        if (sessionStorage.getItem("GOOGLE_ID_TOKEN")) {
            fetchStatus();
        }
    }, 5000); 
});