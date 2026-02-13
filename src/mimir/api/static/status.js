import { apiFetch } from './helpers.js';

/* ── Status dashboard ─────────────────── */

let refreshTimer = null;

export function initStatus() {
  const dash = document.getElementById('statusDashboard');
  if (!dash) return;

  // Auto-refresh when tab is active
  const observer = new MutationObserver(() => {
    if (dash.style.display !== 'none') {
      refreshStatus();
      startAutoRefresh();
    } else {
      stopAutoRefresh();
    }
  });
  observer.observe(dash, { attributes: true, attributeFilter: ['style'] });

  document.getElementById('statusRefreshBtn')?.addEventListener('click', refreshStatus);
}

function startAutoRefresh() {
  stopAutoRefresh();
  refreshTimer = setInterval(refreshStatus, 15000);
}

function stopAutoRefresh() {
  if (refreshTimer) { clearInterval(refreshTimer); refreshTimer = null; }
}

function num(v) { return typeof v === 'number' && isFinite(v) ? v : 0; }

function ago(seconds) {
  if (seconds == null) return 'never';
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

function badge(status) {
  const cls = { completed: 'ok', running: 'running', pending: 'pending', failed: 'err' }[status] || '';
  return `<span class="status-badge ${cls}">${status}</span>`;
}

async function refreshStatus() {
  const grid = document.getElementById('statusGrid');
  if (!grid) return;
  grid.innerHTML = '<div class="status-loading">Loading...</div>';

  try {
    const [statsRes, tasksRes, runsRes] = await Promise.all([
      apiFetch('/api/stats'),
      apiFetch('/api/tasks'),
      apiFetch('/api/runs'),
    ]);
    const stats = await statsRes.json();
    const tasks = await tasksRes.json();
    const runs  = await runsRes.json();

    grid.innerHTML = '';

    // ── 1. Graph Overview card
    grid.innerHTML += buildCard('Knowledge Graph', 'graph', `
      <div class="status-metrics">
        <div class="status-metric">
          <span class="status-metric-val">${num(stats.entities).toLocaleString()}</span>
          <span class="status-metric-label">Entities</span>
        </div>
        <div class="status-metric">
          <span class="status-metric-val">${num(stats.relations).toLocaleString()}</span>
          <span class="status-metric-label">Relations</span>
        </div>
        <div class="status-metric">
          <span class="status-metric-val">${num(stats.metrics?.active_actors || 0).toLocaleString()}</span>
          <span class="status-metric-label">Active Actors (30d)</span>
        </div>
      </div>
    `);

    // ── 2. Ingestion Pipeline card
    const total = num(stats.runs_total);
    const completed = num(stats.runs_completed);
    const failed = num(stats.runs_failed);
    const pending = num(stats.runs_pending);
    const running = num(stats.runs_running);
    const rate = num(stats.rate_per_hour);
    const pct = total > 0 ? ((completed + failed) / total * 100).toFixed(1) : '0.0';

    grid.innerHTML += buildCard('Ingestion Pipeline', 'pipeline', `
      <div class="status-metrics">
        <div class="status-metric">
          <span class="status-metric-val">${total.toLocaleString()}</span>
          <span class="status-metric-label">Total Runs</span>
        </div>
        <div class="status-metric">
          <span class="status-metric-val ok">${completed.toLocaleString()}</span>
          <span class="status-metric-label">Completed</span>
        </div>
        <div class="status-metric">
          <span class="status-metric-val warn">${pending.toLocaleString()}</span>
          <span class="status-metric-label">Pending</span>
        </div>
        <div class="status-metric">
          <span class="status-metric-val accent">${running.toLocaleString()}</span>
          <span class="status-metric-label">Running</span>
        </div>
        <div class="status-metric">
          <span class="status-metric-val err">${failed.toLocaleString()}</span>
          <span class="status-metric-label">Failed</span>
        </div>
        <div class="status-metric">
          <span class="status-metric-val">${rate}</span>
          <span class="status-metric-label">Completed/hr</span>
        </div>
      </div>
      <div class="status-progress-wrap">
        <div class="status-progress-bar">
          <div class="status-progress-fill" style="width:${pct}%"></div>
        </div>
        <span class="status-progress-label">${pct}% processed</span>
      </div>
    `);

    // ── 3. Metrics Health card
    const ms = stats.metrics_status || {};
    const cs = stats.cti_metrics_status || {};
    const metricsHealth = ms.error ? 'err' : ms.is_stale ? 'warn' : ms.last_rollup_at ? 'ok' : 'pending';
    const ctiHealth     = cs.error ? 'err' : cs.is_stale ? 'warn' : cs.last_rollup_at ? 'ok' : 'pending';
    const metricsLabel  = ms.error ? 'Error' : ms.is_stale ? 'Stale' : ms.last_rollup_at ? 'Fresh' : 'Pending';
    const ctiLabel      = cs.error ? 'Error' : cs.is_stale ? 'Stale' : cs.last_rollup_at ? 'Fresh' : 'Pending';

    grid.innerHTML += buildCard('Metrics Health', 'metrics', `
      <div class="status-rows">
        <div class="status-row">
          <span class="status-row-label">Threat Actor Rollup</span>
          <span class="status-badge ${metricsHealth}">${metricsLabel}</span>
          <span class="status-row-detail">${ago(ms.rollup_age_seconds)}</span>
        </div>
        <div class="status-row">
          <span class="status-row-label">CTI Assessment</span>
          <span class="status-badge ${ctiHealth}">${ctiLabel}</span>
          <span class="status-row-detail">${ago(cs.rollup_age_seconds)}</span>
        </div>
        ${ms.error ? `<div class="status-error">${ms.error}</div>` : ''}
        ${cs.error ? `<div class="status-error">${cs.error}</div>` : ''}
      </div>
    `);

    // ── 4. Recent Runs card
    const recentRuns = (runs || []).slice(0, 10);
    const runsHtml = recentRuns.length > 0
      ? recentRuns.map(r => `
        <div class="status-row">
          <span class="status-row-label run-id" title="${r.run_id}">${truncId(r.run_id)}</span>
          ${badge(r.status)}
          <span class="status-row-detail">${r.model || '—'}</span>
          <span class="status-row-detail">${fmtTime(r.started_at)}</span>
        </div>`).join('')
      : '<div class="status-empty">No runs yet</div>';

    grid.innerHTML += buildCard('Recent Runs', 'runs', `
      <div class="status-rows">${runsHtml}</div>
    `);

    // ── 5. Background Tasks card
    const recentTasks = (tasks || []).slice(0, 10);
    const tasksHtml = recentTasks.length > 0
      ? recentTasks.map(t => `
        <div class="status-row">
          <span class="status-row-label">${t.kind}</span>
          ${badge(t.status)}
          <span class="status-row-detail">${t.progress || ''}</span>
          <span class="status-row-detail">${fmtTime(t.started_at)}</span>
          ${t.error ? `<br><span class="status-error-inline">${truncate(t.error, 80)}</span>` : ''}
        </div>`).join('')
      : '<div class="status-empty">No background tasks</div>';

    grid.innerHTML += buildCard('Background Tasks', 'tasks', `
      <div class="status-rows">${tasksHtml}</div>
    `);

    // ── 6. CTI Overview card (if available)
    const cti = stats.cti_metrics;
    if (cti && typeof cti === 'object') {
      const summary = cti.summary || {};
      grid.innerHTML += buildCard('CTI Overview', 'cti', `
        <div class="status-metrics">
          <div class="status-metric">
            <span class="status-metric-val">${num(summary.total_assessments).toLocaleString()}</span>
            <span class="status-metric-label">Assessments</span>
          </div>
          <div class="status-metric">
            <span class="status-metric-val">${num(summary.active_threat_actors).toLocaleString()}</span>
            <span class="status-metric-label">Active Actors</span>
          </div>
          <div class="status-metric">
            <span class="status-metric-val">${num(summary.active_malware).toLocaleString()}</span>
            <span class="status-metric-label">Active Malware</span>
          </div>
          <div class="status-metric">
            <span class="status-metric-val">${summary.avg_threat_level || '—'}</span>
            <span class="status-metric-label">Avg Threat Level</span>
          </div>
        </div>
      `);
    }

  } catch (err) {
    grid.innerHTML = `<div class="status-error-card">
      <h3>Failed to load status</h3>
      <p>${err.message}</p>
    </div>`;
  }
}

/* ── Helpers ─────────────── */

function buildCard(title, icon, body) {
  const icons = {
    graph:    '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="6" cy="6" r="3"/><circle cx="18" cy="18" r="3"/><circle cx="18" cy="6" r="3"/><path d="M8.5 8l7 7M8.5 6h7"/></svg>',
    pipeline: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>',
    metrics:  '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>',
    runs:     '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M3 9h18M9 21V9"/></svg>',
    tasks:    '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2h11"/></svg>',
    cti:      '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
  };
  return `
    <div class="status-card">
      <div class="status-card-header">
        ${icons[icon] || ''}
        <h3>${title}</h3>
      </div>
      <div class="status-card-body">${body}</div>
    </div>`;
}

function truncId(id) {
  if (!id) return '—';
  // Show prefix + last 8 chars
  if (id.length > 24) {
    const parts = id.split('-');
    const prefix = parts[0] || '';
    return prefix + '-…' + id.slice(-8);
  }
  return id;
}

function truncate(s, max) {
  if (!s) return '';
  return s.length > max ? s.slice(0, max) + '…' : s;
}

function fmtTime(iso) {
  if (!iso) return '';
  try {
    const d = new Date(iso);
    const now = new Date();
    const diff = (now - d) / 1000;
    if (diff < 60) return 'just now';
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return d.toLocaleDateString();
  } catch { return iso; }
}
