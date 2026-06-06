// CyberShield Dashboard - Complete Working Version
if (window.socket) { window.socket.disconnect(); }
const socket = io();
let totalThreats = 0, totalBlocked = 0, scannedCount = 0;
let currentFilter = 'all', currentPage = 0, alertsPerPage = 100;
let threatChart = null, moduleChart = null, typeChart = null;

// ============================================================
// VIEW SWITCHING
// ============================================================
function showAnalytics() {
    document.getElementById('mainView').style.display = 'none';
    document.getElementById('analyticsView').style.display = 'flex';
    setTimeout(loadChartData, 300);
}
function showMainView() {
    document.getElementById('mainView').style.display = 'flex';
    document.getElementById('analyticsView').style.display = 'none';
}

// ============================================================
// LOAD ALERTS FROM DATABASE
// ============================================================
function loadAlertsByDate() {
    const hours = document.getElementById('dateRange').value;
    currentPage = 0;
    document.getElementById('alertList').innerHTML = '<div class="empty-state">Loading...</div>';
    
    let url = '/api/alerts?limit=10000';
    if (hours !== 'all') url += '&hours=' + hours;
    
    fetch(url)
        .then(function(r) { return r.json(); })
        .then(function(data) {
            document.getElementById('alertList').innerHTML = '';
            const alerts = Array.isArray(data) ? data : [];
            
            if (alerts.length === 0) {
                document.getElementById('alertList').innerHTML = '<div class="empty-state">No alerts found</div>';
                document.getElementById('alertCount').textContent = '0 alerts';
                document.getElementById('loadMoreBtn').style.display = 'none';
                document.getElementById('totalThreats').textContent = '0';
                document.getElementById('totalBlocked').textContent = '0';
                document.getElementById('scannedCount').textContent = '0';
                return;
            }
            
            document.getElementById('alertCount').textContent = alerts.length + ' alerts';
            document.getElementById('totalThreats').textContent = alerts.length;
            document.getElementById('scannedCount').textContent = alerts.length;
            
            let blocked = 0;
            alerts.forEach(function(alert) {
                addAlertCard(alert);
                if (alert.is_blocked === 1) blocked++;
            });
            
            document.getElementById('totalBlocked').textContent = blocked;
            document.getElementById('loadMoreBtn').style.display = 'none';
        })
        .catch(function() {
            document.getElementById('alertList').innerHTML = '<div class="empty-state">Error loading</div>';
        });
}

function loadMoreAlerts() {
    currentPage++;
    const hours = document.getElementById('dateRange').value;
    const offset = currentPage * alertsPerPage;
    
    let url = '/api/alerts?limit=' + alertsPerPage + '&offset=' + offset;
    if (hours !== 'all') url += '&hours=' + hours;
    
    fetch(url)
        .then(function(r) { return r.json(); })
        .then(function(data) {
            const alerts = Array.isArray(data) ? data : [];
            if (alerts.length === 0) {
                document.getElementById('loadMoreBtn').style.display = 'none';
                return;
            }
            alerts.forEach(function(alert) { addAlertCard(alert); });
            document.getElementById('alertCount').textContent = 
                document.querySelectorAll('.alert-card').length + ' alerts';
        });
}

// ============================================================
// ALERT CARD
// ============================================================
function addAlertCard(alert) {
    const list = document.getElementById('alertList');
    const empty = list.querySelector('.empty-state');
    if (empty) empty.remove();
    
    const card = document.createElement('div');
    const conf = alert.confidence || 0;
    let severity = 'low';
    if (conf >= 0.9) severity = 'critical';
    else if (conf >= 0.75) severity = 'high';
    else if (conf >= 0.6) severity = 'medium';
    
    card.className = 'alert-card ' + severity;
    card.setAttribute('data-module', alert.module || 'unknown');
    card.onclick = function() { showDetails(alert); };
    
    const time = alert.timestamp ? new Date(alert.timestamp).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'}) : '--:--';
    const confPct = (conf * 100).toFixed(0);
    
    let blockedBadge = '';
    if (alert.is_blocked || alert.blocked) {
        if (alert.blocked_type === 'URL') {
            blockedBadge = '<span class="alert-blocked url">🔗 URL BLOCKED</span>';
        } else if (alert.blocked_type === 'EMAIL') {
            blockedBadge = '<span class="alert-blocked email">📧 EMAIL BLOCKED</span>';
        } else if (alert.blocked_type === 'IP') {
            blockedBadge = '<span class="alert-blocked">🛑 IP BLOCKED</span>';
        } else {
            blockedBadge = '<span class="alert-blocked">BLOCKED</span>';
        }
    }
    
    card.innerHTML = `
        <div class="alert-top">
            <span class="alert-type">${getEmoji(alert.module)} ${alert.detection_type || alert.type || 'alert'}</span>
            <span class="alert-time">${time}</span>
        </div>
        <div class="alert-mid">
            <span>${alert.module || 'unknown'}</span>
            <span>${alert.source_ip || 'N/A'}</span>
            ${blockedBadge}
        </div>
        <div class="alert-confidence">${confPct}% confidence</div>
        <div class="conf-bar"><div class="conf-fill" style="width:${confPct}%"></div></div>
    `;
    
    list.appendChild(card);
    
    if (currentFilter !== 'all' && card.getAttribute('data-module') !== currentFilter) {
        card.classList.add('hidden');
    }
}

// ============================================================
// FILTER
// ============================================================
function filterAlerts(filter, chipElement) {
    currentFilter = filter;
    document.querySelectorAll('.module-chip').forEach(function(c) { c.classList.remove('active'); });
    chipElement.classList.add('active');
    
    const names = {'all':'All','url':'URL','email':'Email','app_attack':'App','dpi':'DPI'};
    document.getElementById('filterBadge').textContent = names[filter] || filter;
    
    let visible = 0;
    document.querySelectorAll('.alert-card').forEach(function(card) {
        const mod = card.getAttribute('data-module');
        if (filter === 'all' || mod === filter) {
            card.classList.remove('hidden'); visible++;
        } else {
            card.classList.add('hidden');
        }
    });
    
    const list = document.getElementById('alertList');
    const existingEmpty = list.querySelector('.empty-state');
    if (visible === 0 && !existingEmpty) {
        const empty = document.createElement('div');
        empty.className = 'empty-state';
        empty.textContent = 'No matching alerts';
        list.appendChild(empty);
    } else if (visible > 0 && existingEmpty) {
        existingEmpty.remove();
    }
}

// ============================================================
// DETAIL MODAL
// ============================================================
function showDetails(alert) {
    document.getElementById('modalTitle').textContent = 'Threat Details';
    const conf = ((alert.confidence || 0) * 100).toFixed(1);
    const time = alert.timestamp ? new Date(alert.timestamp).toLocaleString() : 'N/A';
    
    let blockedInfo = '';
    if (alert.blocked_type) {
        if (alert.blocked_type === 'URL') {
            blockedInfo = '<div class="detail-row"><span class="detail-label">Blocked</span><span class="detail-value warning">🔗 URL: ' + (alert.blocked_target || 'N/A') + '</span></div>';
        } else if (alert.blocked_type === 'IP') {
            blockedInfo = '<div class="detail-row"><span class="detail-label">Blocked</span><span class="detail-value danger">🛑 IP: ' + (alert.blocked_target || alert.source_ip || 'N/A') + '</span></div>';
        } else if (alert.blocked_type === 'EMAIL') {
            blockedInfo = '<div class="detail-row"><span class="detail-label">Blocked</span><span class="detail-value" style="color:#8957e5">📧 Sender: ' + (alert.blocked_target || 'N/A') + '</span></div>';
        }
    }
    
    let phishingInfo = '';
    if (alert.phishing_url) {
        phishingInfo = `
            <div class="detail-row"><span class="detail-label">Phishing URL</span><span class="detail-value warning">${alert.phishing_url}</span></div>
            <div class="detail-row"><span class="detail-label">Phishing Domain</span><span class="detail-value warning">${alert.phishing_domain || 'N/A'}</span></div>
        `;
    }
    
    document.getElementById('modalBody').innerHTML = `
        <div class="detail-row"><span class="detail-label">Type</span><span class="detail-value">${alert.detection_type || alert.type || 'N/A'}</span></div>
        <div class="detail-row"><span class="detail-label">Module</span><span class="detail-value">${getEmoji(alert.module)} ${alert.module}</span></div>
        <div class="detail-row"><span class="detail-label">Severity</span><span class="detail-value ${alert.severity==='critical'?'danger':''}">${(alert.severity||'medium').toUpperCase()}</span></div>
        <div class="detail-row"><span class="detail-label">Confidence</span><span class="detail-value">${conf}%</span></div>
        <div class="detail-row"><span class="detail-label">Source IP</span><span class="detail-value">${alert.source_ip||'N/A'}</span></div>
        ${phishingInfo}
        ${blockedInfo}
        <div class="detail-row"><span class="detail-label">Status</span><span class="detail-value ${alert.blocked?'danger':''}">${alert.blocked?'🛑 BLOCKED':'🚨 DETECTED'}</span></div>
        <div class="detail-row"><span class="detail-label">Time</span><span class="detail-value">${time}</span></div>
        <div class="detail-row"><span class="detail-label">Alert ID</span><span class="detail-value">#${alert.id||'N/A'}</span></div>
        ${alert.pi_name ? '<div class="detail-row"><span class="detail-label">Pi Node</span><span class="detail-value">'+alert.pi_name+'</span></div>' : ''}
    `;
    
    document.getElementById('modalOverlay').classList.add('show');
}
function closeModal() { document.getElementById('modalOverlay').classList.remove('show'); }
document.addEventListener('keydown', function(e) { if(e.key==='Escape') closeModal(); });

// ============================================================
// WEBSOCKET - REAL-TIME ALERTS
// ============================================================
socket.on('connect', function() {
    document.getElementById('statusDot').className = 'status-dot';
    document.getElementById('uptime').textContent = 'Live';
});
socket.on('disconnect', function() {
    document.getElementById('statusDot').className = 'status-dot offline';
});
socket.on('new_alert', function(alert) {
    const list = document.getElementById('alertList');
    const empty = list.querySelector('.empty-state');
    if (empty) empty.remove();
    
    addAlertCard(alert);
    
    // Move newest card to top
    const cards = list.querySelectorAll('.alert-card');
    if (cards.length > 1) {
        list.insertBefore(cards[cards.length - 1], cards[0]);
    }
    
    totalThreats++;
    document.getElementById('totalThreats').textContent = totalThreats;
    if (alert.blocked) {
        totalBlocked++;
        document.getElementById('totalBlocked').textContent = totalBlocked;
    }
    scannedCount++;
    document.getElementById('scannedCount').textContent = scannedCount;
});

// ============================================================
// CHARTS
// ============================================================
function loadChartData() {
    const hours = document.getElementById('chartRange').value;
    
    fetch('/api/timeline?hours=' + hours)
        .then(function(r) { return r.json(); })
        .then(function(d) {
            const data = Array.isArray(d) ? d : [];
            renderChart('threatChart', 'line',
                data.map(function(i) { return i.hour ? new Date(i.hour).getHours() + ':00' : ''; }),
                data.map(function(i) { return i.count || 0; }),
                'Threats', '#da3633');
        });
    
    fetch('/api/module_stats')
        .then(function(r) { return r.json(); })
        .then(function(d) {
            const m = d || {};
            renderDoughnut('moduleChart', Object.keys(m),
                Object.values(m).map(function(v) { return v.detections || v || 0; }));
        });
    
    fetch('/api/top_threats?hours=' + hours)
        .then(function(r) { return r.json(); })
        .then(function(d) {
            const data = Array.isArray(d) ? d.slice(0, 5) : [];
            renderChart('typeChart', 'bar',
                data.map(function(i) { return i.detection_type || 'unknown'; }),
                data.map(function(i) { return i.count || 0; }),
                'Count', '#58a6ff');
        });
    
    fetch('/api/stats')
        .then(function(r) { return r.json(); })
        .then(function(d) {
            document.getElementById('analyticsSummary').innerHTML = `
                <h3>Overall Summary</h3>
                <div class="summary-row"><span>Total Alerts</span><span>${d.total_alerts || 0}</span></div>
                <div class="summary-row"><span>Blocked</span><span style="color:#da3633">${d.blocked_threats || 0}</span></div>
                <div class="summary-row"><span>Modules Active</span><span>4</span></div>`;
        });
}

function renderChart(canvasId, type, labels, values, label, color) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (canvasId === 'threatChart' && threatChart) threatChart.destroy();
    if (canvasId === 'moduleChart' && moduleChart) moduleChart.destroy();
    if (canvasId === 'typeChart' && typeChart) typeChart.destroy();
    
    const chart = new Chart(ctx, {
        type: type,
        data: {
            labels: labels,
            datasets: [{
                label: label, data: values,
                borderColor: color,
                backgroundColor: type === 'line' ? color + '20' : color,
                fill: type === 'line', tension: 0.3
            }]
        },
        options: {
            responsive: true, maintainAspectRatio: true,
            plugins: { legend: { labels: { color: '#c9d1d9', font: { size: 10 } } } },
            scales: type !== 'doughnut' ? {
                x: { ticks: { color: '#8b949e', font: { size: 9 } }, grid: { color: '#30363d' } },
                y: { beginAtZero: true, ticks: { color: '#8b949e', font: { size: 9 } }, grid: { color: '#30363d' } }
            } : {}
        }
    });
    
    if (canvasId === 'threatChart') threatChart = chart;
    if (canvasId === 'moduleChart') moduleChart = chart;
    if (canvasId === 'typeChart') typeChart = chart;
}

function renderDoughnut(canvasId, labels, values) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    moduleChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: values.length > 0 ? values : [1],
                backgroundColor: ['#58a6ff', '#d2991d', '#8957e5', '#238636']
            }]
        },
        options: {
            responsive: true,
            plugins: { legend: { labels: { color: '#c9d1d9', font: { size: 10 } } } }
        }
    });
}

// ============================================================
// HELPERS
// ============================================================
function getEmoji(m) {
    var map = {'url':'🔗', 'email':'📧', 'app_attack':'💻', 'dpi':'📊'};
    return map[m] || '🔍';
}

// ============================================================
// INIT
// ============================================================
function init() {
    loadAlertsByDate();
    
    fetch('/api/blocked_ips')
        .then(function(r) { return r.json(); })
        .then(function(d) {
            document.getElementById('activeBlocks').textContent = Array.isArray(d) ? d.length : 0;
        });
    
    setInterval(function() {
        document.getElementById('uptime').textContent = new Date().toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'});
    }, 30000);
    document.getElementById('uptime').textContent = new Date().toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'});
    
    setInterval(function() {
        fetch('/api/blocked_ips')
            .then(function(r) { return r.json(); })
            .then(function(d) {
                document.getElementById('activeBlocks').textContent = Array.isArray(d) ? d.length : 0;
            });
    }, 10000);
}

// Start everything
init();