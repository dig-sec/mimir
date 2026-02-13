import { toast, fmtSize, apiFetch } from './helpers.js';

export function initUpload() {
  const dropZone = document.getElementById('dropZone');
  const fileInput = document.getElementById('fileInput');
  const fileListEl = document.getElementById('fileList');
  const uploadActions = document.getElementById('uploadActions');
  let pendingFiles = [];

  dropZone.addEventListener('click', () => fileInput.click());
  dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('dragover'); });
  dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
  dropZone.addEventListener('drop', e => {
    e.preventDefault();
    dropZone.classList.remove('dragover');
    addFiles(e.dataTransfer.files);
  });
  fileInput.addEventListener('change', () => { addFiles(fileInput.files); fileInput.value = ''; });

  document.getElementById('clearFilesBtn').addEventListener('click', () => {
    pendingFiles = [];
    renderFileList();
  });

  document.getElementById('uploadBtn').addEventListener('click', uploadFiles);

  function addFiles(filesList) {
    for (const f of filesList) pendingFiles.push(f);
    renderFileList();
  }

  function renderFileList() {
    if (!pendingFiles.length) {
      fileListEl.innerHTML = '';
      uploadActions.style.display = 'none';
      return;
    }
    uploadActions.style.display = 'flex';
    fileListEl.innerHTML = pendingFiles.map((f, i) => `
      <div class="file-item">
        <span class="name">${f.name}</span>
        <span class="size">${fmtSize(f.size)}</span>
        <button class="remove-file" data-idx="${i}">&times;</button>
      </div>
    `).join('');
    fileListEl.querySelectorAll('.remove-file').forEach(btn => {
      btn.addEventListener('click', () => {
        pendingFiles.splice(parseInt(btn.dataset.idx), 1);
        renderFileList();
      });
    });
  }

  async function uploadFiles() {
    if (!pendingFiles.length) return;
    const btn = document.getElementById('uploadBtn');
    btn.disabled = true;
    btn.textContent = 'Uploading...';
    try {
      const fd = new FormData();
      pendingFiles.forEach(f => fd.append('files', f));
      const res = await apiFetch('/api/upload', { method: 'POST', body: fd });
      if (!res.ok) throw new Error('Upload failed');
      const data = await res.json();
      // Summarise STIX vs regular uploads
      const stixResults = data.filter(r => r.type === 'stix');
      const regularResults = data.filter(r => r.type !== 'stix');
      const msgs = [];
      if (stixResults.length) {
        const ents = stixResults.reduce((s, r) => s + (r.entities || 0), 0);
        const rels = stixResults.reduce((s, r) => s + (r.relations || 0), 0);
        msgs.push(`STIX: ${ents} entities, ${rels} relations imported`);
      }
      if (regularResults.length) {
        msgs.push(`${regularResults.length} file(s) queued for extraction`);
      }
      toast(msgs.join(' · ') || 'Upload complete', 'success');
      pendingFiles = [];
      renderFileList();
      document.dispatchEvent(new Event('loadRuns'));
      data.forEach(r => { if (r.run_id) pollRun(r.run_id); });
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      btn.disabled = false;
      btn.textContent = 'Upload & Process';
    }
  }
}

/* ── runs list ─────────────────────────── */
export function initRuns() {
  const runsToggle = document.getElementById('runsToggle');
  const runsContent = document.getElementById('runsContent');
  let runsOpen = false;

  runsToggle.addEventListener('click', () => {
    runsOpen = !runsOpen;
    runsContent.style.display = runsOpen ? 'block' : 'none';
    runsToggle.innerHTML = (runsOpen ? '&#9660;' : '&#9654;') + ' Recent runs';
    if (runsOpen) loadRuns();
  });

  document.getElementById('refreshRunsBtn').addEventListener('click', loadRuns);
  document.addEventListener('loadRuns', () => {
    runsOpen = true;
    runsContent.style.display = 'block';
    runsToggle.innerHTML = '&#9660; Recent runs';
    loadRuns();
  });

  document.getElementById('clearRunsBtn').addEventListener('click', async () => {
    if (!confirm('Delete all runs?')) return;
    try {
      const res = await apiFetch('/api/runs', { method: 'DELETE' });
      if (!res.ok) throw new Error('Failed to clear runs');
      const data = await res.json();
      toast(`Cleared ${data.deleted} run(s)`, 'success');
      loadRuns();
    } catch (e) {
      toast(e.message, 'error');
    }
  });
}

async function loadRuns() {
  try {
    const res = await apiFetch('/api/runs');
    const runs = await res.json();
    const el = document.getElementById('runsContent');
    if (!runs.length) {
      el.innerHTML = '<div class="empty-state" style="padding:20px 0"><p>No runs yet</p></div>';
      return;
    }
    el.innerHTML = runs.map(r => `
      <div class="run-item" data-run="${r.run_id}">
        <span class="name" title="${r.run_id}">${r.run_id.slice(0, 8)}…</span>
        <span class="badge ${r.status}">${r.status}</span>
      </div>
    `).join('');
  } catch (e) { /* silent */ }
}

function pollRun(runId) {
  const iv = setInterval(async () => {
    try {
      const res = await apiFetch('/runs/' + runId);
      const data = await res.json();
      const status = data.run.status;
      if (status === 'completed' || status === 'failed') {
        clearInterval(iv);
        toast(
          `Run ${runId.slice(0, 8)}… ${status}`,
          status === 'completed' ? 'success' : 'error'
        );
        loadRuns();
      }
    } catch (e) {
      clearInterval(iv);
    }
  }, 3000);
}
