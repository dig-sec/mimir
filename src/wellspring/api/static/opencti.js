import { toast, apiFetch } from './helpers.js';

export function initOpenCTI() {
  document.getElementById('scanFilesBtn').addEventListener('click', scanFiles);
  document.getElementById('elasticPullBtn').addEventListener('click', pullElasticsearchDocs);
  document.getElementById('feedlyPullBtn').addEventListener('click', pullFeedly);
  document.getElementById('openctiPullBtn').addEventListener('click', pullOpenCTI);
  document.getElementById('pullAllBtn').addEventListener('click', pullAllSources);

  // Load watched folder names into button label
  loadWatchedFolders();

  // Poll stats every 5s
  refreshStats();
  setInterval(refreshStats, 5000);

  // Check for any running tasks on load
  checkTasks();
}

let watchedFolderLabel = 'Watched Folders';

async function loadWatchedFolders() {
  try {
    const res = await apiFetch('/api/watched-folders');
    const folders = await res.json();
    if (folders.length > 0) {
      const names = folders.map(f => f.path.split('/').pop()).join(', ');
      const total = folders.reduce((s, f) => s + f.file_count, 0);
      watchedFolderLabel = names;
      const btn = document.getElementById('scanFilesBtn');
      btn.innerHTML = `&#x1F4C1; Scan ${names} (${total.toLocaleString()} files)`;
    }
  } catch (e) { /* silent */ }
}

async function refreshStats() {
  try {
    const res = await apiFetch('/api/stats');
    const s = await res.json();

    // Header stats bar (compact)
    const bar = document.getElementById('statsBar');
    const activeActors = s.metrics?.active_actors || 0;
    const metricsStatus = s.metrics_status || {};
    let metricsFresh = 'metrics pending';
    if (metricsStatus.error) metricsFresh = 'metrics error';
    else if (!metricsStatus.last_rollup_at) metricsFresh = 'metrics pending';
    else if (metricsStatus.is_stale) metricsFresh = 'metrics stale';
    else metricsFresh = 'metrics fresh';
    bar.textContent =
      `${s.entities.toLocaleString()} entities · ${s.relations.toLocaleString()} rels` +
      ` · ${activeActors.toLocaleString()} active actors (30d)` +
      ` · ${metricsFresh}`;

    // Ingestion progress bar
    const total = s.runs_total || 1;
    const done = s.runs_completed + s.runs_failed;
    const pct = Math.min(100, (done / total) * 100);

    const counts = document.getElementById('ingestCounts');
    const fill = document.getElementById('ingestFill');
    const rate = document.getElementById('ingestRate');
    const ingestBar = document.getElementById('ingestBar');

    if (s.runs_pending === 0 && s.runs_running === 0) {
      ingestBar.classList.add('hidden');
      return;
    }
    ingestBar.classList.remove('hidden');

    fill.style.width = pct.toFixed(1) + '%';

    counts.innerHTML =
      `<span class="val">${done.toLocaleString()}</span>/${total.toLocaleString()} runs ` +
      `· <span class="val">${s.runs_pending.toLocaleString()}</span> pending` +
      (s.runs_running ? ` · <span class="val">${s.runs_running}</span> active` : '') +
      (s.runs_failed ? ` · <span style="color:#ef4444">${s.runs_failed}</span> failed` : '');

    if (s.rate_per_hour > 0) {
      const hoursLeft = s.runs_pending / s.rate_per_hour;
      let eta;
      if (hoursLeft < 1) eta = `${Math.round(hoursLeft * 60)}m`;
      else if (hoursLeft < 48) eta = `${Math.round(hoursLeft)}h`;
      else eta = `${Math.round(hoursLeft / 24)}d`;
      rate.innerHTML = `<span class="active">${s.rate_per_hour}/hr</span> · ETA ${eta}`;
    } else {
      rate.innerHTML = s.runs_running ? '<span class="active">processing…</span>' : 'idle';
    }
  } catch (e) { /* silent */ }
}

async function scanFiles() {
  const btn = document.getElementById('scanFilesBtn');
  btn.disabled = true;
  btn.textContent = 'Scanning...';

  try {
    // Scan all watched folders
    const res = await apiFetch('/api/scan', { method: 'POST' });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || 'Scan failed');
    }

    const data = await res.json();
    toast(`Scan started (task ${data.task_id})`, 'success');
    pollTask(data.task_id);

  } catch (e) {
    toast(e.message, 'error');
  } finally {
    btn.disabled = false;
    btn.innerHTML = `&#x1F4C1; Scan ${watchedFolderLabel}`;
  }
}

async function pullElasticsearchDocs() {
  const btn = document.getElementById('elasticPullBtn');
  btn.disabled = true;
  btn.textContent = 'Pulling...';

  try {
    const res = await apiFetch('/api/elasticsearch/pull', { method: 'POST' });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || 'Elasticsearch pull failed');
    }

    const data = await res.json();
    toast(`Elasticsearch pull started (task ${data.task_id})`, 'success');
    pollTask(data.task_id);

  } catch (e) {
    toast(e.message, 'error');
  } finally {
    btn.disabled = false;
    btn.innerHTML = '&#x1F50D; ES Docs';
  }
}

async function pullFeedly() {
  const btn = document.getElementById('feedlyPullBtn');
  btn.disabled = true;
  btn.textContent = 'Pulling...';

  try {
    const res = await apiFetch('/api/feedly/pull', { method: 'POST' });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || 'Feedly pull failed');
    }

    const data = await res.json();
    toast(`Feedly pull started (task ${data.task_id})`, 'success');
    pollTask(data.task_id);

  } catch (e) {
    toast(e.message, 'error');
  } finally {
    btn.disabled = false;
    btn.innerHTML = '&#x1F4E1; Feedly CTI';
  }
}

async function pullOpenCTI() {
  const btn = document.getElementById('openctiPullBtn');
  btn.disabled = true;
  btn.textContent = 'Pulling...';

  try {
    const res = await apiFetch('/api/opencti/pull', { method: 'POST' });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || 'OpenCTI pull failed');
    }

    const data = await res.json();
    toast(`OpenCTI pull started (task ${data.task_id})`, 'success');
    pollTask(data.task_id);

  } catch (e) {
    toast(e.message, 'error');
  } finally {
    btn.disabled = false;
    btn.innerHTML = '&#x1F310; OpenCTI';
  }
}

async function pullAllSources() {
  const btn = document.getElementById('pullAllBtn');
  btn.disabled = true;
  btn.textContent = 'Pulling all sources...';

  try {
    const res = await apiFetch('/api/sources/pull-all', { method: 'POST' });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || 'Pull-all failed');
    }

    const data = await res.json();
    toast(`Pull-all started (task ${data.task_id})`, 'success');
    pollTask(data.task_id);

  } catch (e) {
    toast(e.message, 'error');
  } finally {
    btn.disabled = false;
    btn.innerHTML = '&#x1F504; Pull All Sources';
  }
}

function pollTask(taskId) {
  const bar = document.getElementById('taskBar');
  const badge = document.getElementById('taskBadge');
  const progress = document.getElementById('taskProgress');
  bar.style.display = 'flex';

  const iv = setInterval(async () => {
    try {
      const res = await apiFetch('/api/tasks/' + taskId);
      const t = await res.json();

      badge.textContent = t.status;
      badge.className = 'task-badge ' + t.status;
      progress.textContent = t.progress || '';

      if (t.status === 'completed' || t.status === 'failed') {
        clearInterval(iv);
        toast(
          t.status === 'completed' ? t.progress : `Task failed: ${t.error}`,
          t.status === 'completed' ? 'success' : 'error'
        );
        refreshStats();
        // Auto-hide bar after 15s
        setTimeout(() => { bar.style.display = 'none'; }, 15000);
      }
    } catch (e) {
      clearInterval(iv);
    }
  }, 2000);
}

async function checkTasks() {
  try {
    const res = await apiFetch('/api/tasks');
    const tasks = await res.json();
    const running = tasks.find(t => t.status === 'running');
    if (running) pollTask(running.id);
  } catch (e) { /* silent */ }
}
