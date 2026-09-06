let cachedHistory = [];
let cveChartInstance = null;
let notifications = [];

/**
 * Utility helper to extract CSS variable values with optional fallbacks
 */
function getThemeColor(varName, fallback) {
    const val = getComputedStyle(document.documentElement).getPropertyValue(varName).trim();
    return val || fallback;
}

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

/**
 * Notification Handlers
 */
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

/**
 * Fetch status and polling
 */
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

/**
 * Table rendering with Serial #, App Name, and updated Action Buttons
 */
function renderTable() {
    const list = document.getElementById('completed-apps');
    if (!list) return;

    list.innerHTML = '';
    const searchInput = document.getElementById('search');
    const query = (searchInput ? searchInput.value : '').toLowerCase().trim();

    const filtered = cachedHistory.filter(item => 
        !query || 
        (item.package && item.package.toLowerCase().includes(query)) ||
        (item.app_name && item.app_name.toLowerCase().includes(query))
    );

    if (filtered.length === 0) {
        list.innerHTML = `<tr><td colspan="5" style="text-align:center; color: var(--text-muted);">No records found.</td></tr>`;
        return;
    }

    filtered.forEach((item, index) => {
        const row = document.createElement('tr');
        const appName = item.app_name || item.package.split('.').pop();

        row.innerHTML = `
            <td style="color: var(--text-muted); text-align: center;">${index + 1}</td>
            <td style="font-weight: 600; color: var(--text-main);">${appName}</td>
            <td><code>${item.package}</code></td>
            <td style="color: var(--text-muted);">${item.timestamp}</td>
            <td>
                <div class="report-actions">
                    <button class="report-btn" onclick="viewReport('${item.package}', 'secrets.txt.enc')">Secrets</button>
                    <button class="report-btn" onclick="viewReport('${item.package}', 'mobsfscan.json.enc')">Static Recon</button>
                    <button class="report-btn" onclick="viewReport('${item.package}', 'dynamic_recon.json.enc')">Dynamic Recon</button>
                    <button class="report-btn cve" onclick="viewReport('${item.package}', 'cve.json.enc')">Trivy CVE</button>
                </div>
            </td>
        `;
        list.appendChild(row);
    });

    // Re-initialize SVG icons for newly injected dynamic elements if needed
    if (window.lucide) {
        lucide.createIcons();
    }
}

/**
 * Instant Chart.js Render using cve_summary metrics from status.json
 */
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

    const dangerColor  = getThemeColor('--critical', getThemeColor('--danger', '#ef4444'));
    const warningColor = getThemeColor('--medium', getThemeColor('--warning', '#f59e0b'));
    const accentColor  = getThemeColor('--low', getThemeColor('--accent', '#38bdf8'));
    const textMainColor  = getThemeColor('--text-main', '#f8fafc');
    const textMutedColor = getThemeColor('--text-muted', '#94a3b8');
    const borderColor   = getThemeColor('--border', 'rgba(51, 65, 85, 0.6)');

    cveChartInstance = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels.length > 0 ? labels : ['No Data'],
            datasets: [
                { label: 'High / Critical', data: high, backgroundColor: dangerColor, borderRadius: 4 },
                { label: 'Medium', data: medium, backgroundColor: warningColor, borderRadius: 4 },
                { label: 'Low', data: low, backgroundColor: accentColor, borderRadius: 4 }
            ]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: { 
                    stacked: true, 
                    grid: { color: borderColor }, 
                    ticks: { color: textMutedColor } 
                },
                y: { 
                    stacked: true, 
                    grid: { display: false }, 
                    ticks: { color: textMainColor } 
                }
            },
            plugins: {
                legend: { 
                    position: 'top', 
                    labels: { color: textMainColor, font: { family: 'Inter' } } 
                }
            }
        }
    });
}

async function viewReport(packageName, fileName) {
    const modal = document.getElementById('reportModal');
    const modalTitle = document.getElementById('modalTitle');
    const modalBody = document.getElementById('modalBody');

    if (!modal || !modalTitle || !modalBody) return;

    modalTitle.textContent = `${packageName} — ${fileName.replace('.enc', '')}`;
    modalBody.textContent = "Loading report...";
    modal.style.display = "block";

    try {
        const workerUrl = `https://apkrack.locamartin.workers.dev/api/report?package=${encodeURIComponent(packageName)}&file=${encodeURIComponent(fileName)}`;
        const response = await fetch(workerUrl);

        if (!response.ok) {
            throw new Error("Not Allowed: Decryption Not Detected");
        }

        const dataText = await response.text();

        try {
            const parsedJson = JSON.parse(dataText);
            modalBody.textContent = JSON.stringify(parsedJson, null, 2);
        } catch (e) {
            modalBody.textContent = dataText;
        }
    } catch (err) {
        modalBody.textContent = err.message || "Not Allowed: Decryption Not Detected";
    }
}

function closeModal() {
    const modal = document.getElementById('reportModal');
    if (modal) modal.style.display = "none";
}

document.addEventListener('DOMContentLoaded', () => {
    fetchStatus();
    if (window.lucide) {
        lucide.createIcons();
    }
    setInterval(fetchStatus, 5000); 
});