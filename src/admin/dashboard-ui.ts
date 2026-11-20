// Static admin dashboard. Served with a strict CSP; all dynamic data is rendered via textContent.
export const DASHBOARD_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Gatekeeper Proxy - Admin Dashboard</title>
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
      font-family: system-ui, -apple-system, 'Segoe UI', sans-serif;
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
      font-family: ui-monospace, 'SFMono-Regular', Menlo, Consolas, monospace;
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
      font-family: ui-monospace, 'SFMono-Regular', Menlo, Consolas, monospace;
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
  
    .auth-bar { display: flex; gap: 8px; align-items: center; margin-bottom: 20px; }
    .auth-bar input { flex: 1; max-width: 360px; }
    .notice { font-size: 13px; color: var(--text-muted); min-height: 18px; }
    .notice.error { color: var(--danger); }
    .route-item { padding: 8px; background: rgba(255,255,255,0.03); border-radius: 6px; margin-bottom: 6px; }
    .route-prefix { color: var(--accent); }
    .empty { text-align: center; color: var(--text-muted); }
    .path-cell { word-break: break-all; }
  </style>
</head>
<body>
  <header>
    <div class="brand">
      <span class="brand-icon" aria-hidden="true">&#128737;</span>
      <div>
        <h1>Gatekeeper Proxy</h1>
        <p style="font-size: 12px; color: var(--text-muted);">Reverse proxy with IP rules, request signatures and rate limiting</p>
      </div>
    </div>
    <div class="status-badge" id="status-badge"><span class="pulse"></span><span id="status-text">Connecting...</span></div>
  </header>

  <form class="auth-bar" id="auth-form">
    <input type="password" id="input-token" placeholder="Admin token (leave empty if the admin API has no token)" autocomplete="off" aria-label="Admin token">
    <button class="btn" type="submit">Connect</button>
  </form>

  <div class="metrics-grid">
    <div class="metric-card"><div class="metric-title">Total Requests</div><div class="metric-value" id="val-total-reqs">0</div></div>
    <div class="metric-card"><div class="metric-title">Avg Req/s Since Start</div><div class="metric-value" id="val-rps">0</div></div>
    <div class="metric-card"><div class="metric-title">Firewall Blocks</div><div class="metric-value" style="color: var(--danger);" id="val-waf-blocks">0</div></div>
    <div class="metric-card"><div class="metric-title">Rate Limit Hits</div><div class="metric-value" style="color: var(--warning);" id="val-rate-hits">0</div></div>
    <div class="metric-card"><div class="metric-title">Uptime</div><div class="metric-value" id="val-uptime">0s</div></div>
  </div>

  <div class="grid-two">
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">Recent Security Events</div>
        <span style="font-size: 12px; color: var(--text-muted);">Last 100 firewall and rate-limit rejections (in memory)</span>
      </div>
      <table>
        <thead><tr><th>Time (UTC)</th><th>IP Address</th><th>Method</th><th>Path</th><th>Reason</th></tr></thead>
        <tbody id="events-table-body"><tr><td colspan="5" class="empty">No security events recorded yet.</td></tr></tbody>
      </table>
    </div>

    <div class="panel">
      <div class="panel-header"><div class="panel-title">Firewall Action</div></div>
      <form id="block-form" style="margin-bottom: 16px;">
        <label for="input-block-ip" style="display: block; font-size: 13px; color: var(--text-muted); margin-bottom: 8px;">Block an IP address or CIDR range:</label>
        <input type="text" id="input-block-ip" placeholder="e.g. 203.0.113.7 or 198.51.100.0/24" style="width: 100%; margin-bottom: 10px;">
        <button class="btn" type="submit" style="width: 100%; background: var(--danger);">Add to IP Blacklist</button>
        <p class="notice" id="block-notice" role="status"></p>
      </form>
      <div style="margin-top: 24px;">
        <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 8px;">Configured Routes:</p>
        <div id="routes-list" style="font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 12px;">Loading routes...</div>
      </div>
    </div>
  </div>
  <script src="/_admin/app.js"></script>
</body>
</html>
`;

export const DASHBOARD_JS = String.raw`'use strict';
(function () {
  var TOKEN_KEY = 'gatekeeper-admin-token';
  var $ = function (id) { return document.getElementById(id); };

  function token() { return sessionStorage.getItem(TOKEN_KEY) || ''; }

  function api(path, options) {
    options = options || {};
    var headers = Object.assign({}, options.headers || {});
    if (token()) headers['Authorization'] = 'Bearer ' + token();
    return fetch(path, Object.assign({}, options, { headers: headers })).then(function (res) {
      if (res.status === 401) throw new Error('Unauthorized: enter a valid admin token');
      return res.json().then(function (body) {
        if (!res.ok) throw new Error(body.error || ('HTTP ' + res.status));
        return body;
      });
    });
  }

  // Event fields come from attacker-controlled requests: only ever render them as text.
  function cell(text, className) {
    var td = document.createElement('td');
    if (className) {
      var span = document.createElement('span');
      span.className = className;
      span.textContent = text;
      td.appendChild(span);
    } else {
      td.textContent = text;
    }
    return td;
  }

  function setStatus(ok, text) {
    $('status-text').textContent = text;
    $('status-badge').style.opacity = ok ? '1' : '0.5';
  }

  function renderEvents(events) {
    var tbody = $('events-table-body');
    tbody.replaceChildren();
    if (!events || events.length === 0) {
      var row = document.createElement('tr');
      var td = cell('No security events recorded yet.');
      td.colSpan = 5;
      td.className = 'empty';
      row.appendChild(td);
      tbody.appendChild(row);
      return;
    }
    events.forEach(function (e) {
      var row = document.createElement('tr');
      row.setAttribute('data-event-type', e.type);
      row.appendChild(cell(String(e.timestamp).slice(11, 19)));
      row.appendChild(cell(e.ip));
      row.appendChild(cell(e.method, 'tag tag-warning'));
      var pathCell = cell(e.path);
      pathCell.className = 'path-cell';
      row.appendChild(pathCell);
      row.appendChild(cell(e.reason, 'tag tag-danger'));
      tbody.appendChild(row);
    });
  }

  function fetchMetrics() {
    return api('/api/metrics').then(function (data) {
      $('val-total-reqs').textContent = String(data.totalRequests);
      $('val-rps').textContent = String(data.averageRequestsPerSecond);
      $('val-waf-blocks').textContent = String(data.wafBlocks);
      $('val-rate-hits').textContent = String(data.rateLimitHits);
      $('val-uptime').textContent = data.uptimeSeconds + 's';
      renderEvents(data.recentEvents);
      setStatus(true, 'Connected');
    }).catch(function (err) { setStatus(false, err.message); });
  }

  function fetchRoutes() {
    return api('/api/routes').then(function (routes) {
      var list = $('routes-list');
      list.replaceChildren();
      if (routes.length === 0) list.textContent = 'No routes configured.';
      routes.forEach(function (r) {
        var item = document.createElement('div');
        item.className = 'route-item';
        var prefix = document.createElement('span');
        prefix.className = 'route-prefix';
        prefix.textContent = r.pathPrefix;
        item.appendChild(prefix);
        item.appendChild(document.createTextNode(' \u2192 ' + r.targets.join(', ')));
        list.appendChild(item);
      });
    }).catch(function (err) { $('routes-list').textContent = err.message; });
  }

  $('auth-form').addEventListener('submit', function (ev) {
    ev.preventDefault();
    sessionStorage.setItem(TOKEN_KEY, $('input-token').value.trim());
    $('input-token').value = '';
    fetchMetrics();
    fetchRoutes();
  });

  $('block-form').addEventListener('submit', function (ev) {
    ev.preventDefault();
    var notice = $('block-notice');
    var ip = $('input-block-ip').value.trim();
    if (!ip) return;
    api('/api/firewall/blacklist', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip: ip })
    }).then(function (body) {
      notice.className = 'notice';
      notice.textContent = body.changed ? ('Blocked ' + ip) : (ip + ' was already blocked');
      $('input-block-ip').value = '';
      fetchMetrics();
    }).catch(function (err) {
      notice.className = 'notice error';
      notice.textContent = err.message;
    });
  });

  setInterval(fetchMetrics, 2000);
  fetchMetrics();
  fetchRoutes();
})();
`;
