export function getDashboardHtml(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Gatekeeper-Proxy // Admin & Security Dashboard</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Outfit:wght@400;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #0b0f19;
      --card-bg: #111827;
      --border: #1f2937;
      --accent: #8b5cf6;
      --accent-glow: rgba(139, 92, 246, 0.15);
      --danger: #ef4444;
      --success: #10b981;
      --warning: #f59e0b;
      --text: #f3f4f6;
      --text-muted: #9ca3af;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg);
      color: var(--text);
      font-family: 'Outfit', sans-serif;
      padding: 24px;
      line-height: 1.5;
    }

    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-bottom: 20px;
      border-bottom: 1px solid var(--border);
      margin-bottom: 24px;
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .brand-icon {
      font-size: 28px;
    }

    .brand h1 {
      font-size: 24px;
      font-weight: 700;
      background: linear-gradient(135deg, #a78bfa, #ec4899);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }

    .status-badge {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 6px 12px;
      border-radius: 9999px;
      background: rgba(16, 185, 129, 0.1);
      border: 1px solid rgba(16, 185, 129, 0.3);
      color: var(--success);
      font-size: 13px;
      font-weight: 600;
    }

    .pulse {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background-color: var(--success);
      box-shadow: 0 0 8px var(--success);
      animation: pulse 2s infinite;
    }

    @keyframes pulse {
      0% { opacity: 0.4; }
      50% { opacity: 1; }
      100% { opacity: 0.4; }
    }

    .metrics-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }

    .metric-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 20px;
      position: relative;
      overflow: hidden;
    }

    .metric-title {
      font-size: 13px;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-bottom: 8px;
    }

    .metric-value {
      font-size: 28px;
      font-weight: 700;
      font-family: 'JetBrains Mono', monospace;
    }

    .grid-two {
      display: grid;
      grid-template-columns: 2fr 1fr;
      gap: 20px;
    }

    @media (max-width: 900px) {
      .grid-two { grid-template-columns: 1fr; }
    }

    .panel {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 20px;
      margin-bottom: 24px;
    }

    .panel-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 16px;
      padding-bottom: 12px;
      border-bottom: 1px solid var(--border);
    }

    .panel-title {
      font-size: 16px;
      font-weight: 600;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      font-family: 'JetBrains Mono', monospace;
      font-size: 13px;
    }

    th, td {
      padding: 10px 12px;
      text-align: left;
      border-bottom: 1px solid var(--border);
    }

    th {
      color: var(--text-muted);
      font-weight: 600;
      text-transform: uppercase;
      font-size: 11px;
    }

    .tag {
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 600;
    }

    .tag-danger { background: rgba(239, 68, 68, 0.15); color: var(--danger); }
    .tag-warning { background: rgba(245, 158, 11, 0.15); color: var(--warning); }
    .tag-success { background: rgba(16, 185, 129, 0.15); color: var(--success); }

    .btn {
      background: var(--accent);
      color: white;
      border: none;
      padding: 8px 14px;
      border-radius: 6px;
      font-weight: 600;
      cursor: pointer;
      font-size: 13px;
      transition: opacity 0.2s;
    }

    .btn:hover { opacity: 0.9; }

    input, select {
      background: #0b0f19;
      border: 1px solid var(--border);
      color: white;
      padding: 8px 12px;
      border-radius: 6px;
      font-family: inherit;
      margin-right: 8px;
    }
  </style>
</head>
<body>
  <header>
    <div class="brand">
      <span class="brand-icon">🛡️</span>
      <div>
        <h1>Gatekeeper-Proxy</h1>
        <p style="font-size: 12px; color: var(--text-muted);">Dynamic Reverse Proxy, WAF & Rate Limiting Engine</p>
      </div>
    </div>
    <div class="status-badge">
      <span class="pulse"></span>
      SYSTEM ONLINE & PROTECTED
    </div>
  </header>

  <div class="metrics-grid">
    <div class="metric-card">
      <div class="metric-title">Total Requests</div>
      <div class="metric-value" id="val-total-reqs">0</div>
    </div>
    <div class="metric-card">
      <div class="metric-title">Requests / Sec</div>
      <div class="metric-value" id="val-rps">0.00</div>
    </div>
    <div class="metric-card">
      <div class="metric-title">WAF Blocks</div>
      <div class="metric-value" style="color: var(--danger);" id="val-waf-blocks">0</div>
    </div>
    <div class="metric-card">
      <div class="metric-title">Rate Limit Hits</div>
      <div class="metric-value" style="color: var(--warning);" id="val-rate-hits">0</div>
    </div>
    <div class="metric-card">
      <div class="metric-title">Uptime</div>
      <div class="metric-value" id="val-uptime">0s</div>
    </div>
  </div>

  <div class="grid-two">
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">⚠️ Security Threat Log & Blocked Events</div>
        <span style="font-size: 12px; color: var(--text-muted);">Real-time WAF & Rate Limit Triggers</span>
      </div>
      <table>
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>IP Address</th>
            <th>Method</th>
            <th>Path</th>
            <th>Reason</th>
          </tr>
        </thead>
        <tbody id="events-table-body">
          <tr><td colspan="5" style="text-align: center; color: var(--text-muted);">No security block events recorded yet.</td></tr>
        </tbody>
      </table>
    </div>

    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">🛡️ Quick Firewall Action</div>
      </div>
      <div style="margin-bottom: 16px;">
        <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 8px;">Block IP Address dynamically:</p>
        <input type="text" id="input-block-ip" placeholder="e.g. 192.168.1.100" style="width: 100%; margin-bottom: 10px;">
        <button class="btn" style="width: 100%; background: var(--danger);" onclick="blockIp()">Add to IP Blacklist</button>
      </div>

      <div style="margin-top: 24px;">
        <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 8px;">Configured Routes:</p>
        <div id="routes-list" style="font-family: 'JetBrains Mono', monospace; font-size: 12px;">Loading routes...</div>
      </div>
    </div>
  </div>

  <script>
    async function fetchMetrics() {
      try {
        const res = await fetch('/api/metrics');
        const data = await res.json();
        
        document.getElementById('val-total-reqs').innerText = data.totalRequests;
        document.getElementById('val-rps').innerText = data.requestsPerSecond;
        document.getElementById('val-waf-blocks').innerText = data.wafBlocks;
        document.getElementById('val-rate-hits').innerText = data.rateLimitHits;
        document.getElementById('val-uptime').innerText = data.uptimeSeconds + 's';

        const tbody = document.getElementById('events-table-body');
        if (data.recentEvents && data.recentEvents.length > 0) {
          tbody.innerHTML = data.recentEvents.map(e => \`
            <tr>
              <td style="color: var(--text-muted);">\${e.timestamp.split('T')[1].split('.')[0]}</td>
              <td>\${e.ip}</td>
              <td><span class="tag tag-warning">\${e.method}</span></td>
              <td>\${e.path}</td>
              <td><span class="tag tag-danger">\${e.reason}</span></td>
            </tr>
          \`).join('');
        } else {
          tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">No security block events recorded yet.</td></tr>';
        }
      } catch (err) {
        console.error('Failed to fetch metrics:', err);
      }
    }

    async function fetchRoutes() {
      try {
        const res = await fetch('/api/routes');
        const routes = await res.json();
        const container = document.getElementById('routes-list');
        container.innerHTML = routes.map(r => \`
          <div style="padding: 8px; background: rgba(255,255,255,0.03); border-radius: 6px; margin-bottom: 6px;">
            <span style="color: var(--accent);">\${r.pathPrefix}</span> &rarr; \${r.targets.join(', ')}
          </div>
        \`).join('');
      } catch (err) {
        console.error('Failed to fetch routes', err);
      }
    }

    async function blockIp() {
      const ip = document.getElementById('input-block-ip').value.trim();
      if (!ip) return alert('Please enter a valid IP address');

      await fetch('/api/firewall/blacklist', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip })
      });

      alert('IP ' + ip + ' added to blacklist successfully!');
      document.getElementById('input-block-ip').value = '';
      fetchMetrics();
    }

    setInterval(fetchMetrics, 2000);
    fetchMetrics();
    fetchRoutes();
  </script>
</body>
</html>`;
}
