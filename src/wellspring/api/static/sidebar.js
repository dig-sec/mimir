import { toast, apiFetch } from './helpers.js';

/* ── tab switching ─────────────────────── */
export function initTabs() {
  const sidebar    = document.querySelector('.sidebar');
  const graphArea  = document.querySelector('.graph-area');
  const pirDash    = document.getElementById('pirDashboard');

  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');

      const tab = btn.dataset.tab;
      if (tab === 'pir') {
        /* full-width PIR dashboard */
        sidebar.style.display   = 'none';
        graphArea.style.display = 'none';
        if (pirDash) pirDash.style.display = '';
      } else {
        /* normal sidebar + graph */
        sidebar.style.display   = '';
        graphArea.style.display = '';
        if (pirDash) pirDash.style.display = 'none';
        document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
        const name = tab.charAt(0).toUpperCase() + tab.slice(1);
        document.getElementById('panel' + name)?.classList.add('active');
      }
    });
  });
}

/* ── search + entity selection ─────────── */
export function initSearch(onVisualize) {
  const searchInput = document.getElementById('searchInput');
  const entityList = document.getElementById('entityList');
  const entityTypeInput = document.getElementById('entityTypeInput');
  const entityIdInput = document.getElementById('entityIdInput');
  const confInput = document.getElementById('confInput');
  const confVal = document.getElementById('confVal');
  const sinceInput = document.getElementById('sinceInput');
  const untilInput = document.getElementById('untilInput');
  const timelineIntervalInput = document.getElementById('timelineInterval');
  const timelineToggleInput = document.getElementById('timelineToggle');
  let selectedEntity = null;
  let searchTimer;

  confInput.addEventListener('input', () => {
    confVal.textContent = confInput.value;
  });

  searchInput.addEventListener('input', () => {
    selectedEntity = null;
    if (entityIdInput) entityIdInput.value = '';
    clearTimeout(searchTimer);
    const q = searchInput.value.trim();
    if (!q) {
      entityList.innerHTML = '<div class="empty-state" style="padding:40px 0"><p>Type to search entities</p></div>';
      return;
    }
    searchTimer = setTimeout(() => doSearch(q), 250);
  });

  searchInput.addEventListener('keydown', e => {
    if (e.key === 'Enter') fireVisualize();
  });

  entityTypeInput?.addEventListener('change', () => {
    const q = searchInput.value.trim();
    if (!q) return;
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => doSearch(q), 100);
  });

  entityIdInput?.addEventListener('input', () => {
    const typedId = entityIdInput.value.trim();
    if (typedId) selectedEntity = null;
  });

  document.getElementById('vizBtn').addEventListener('click', fireVisualize);

  async function doSearch(q) {
    try {
      const query = new URLSearchParams({ q });
      const entityType = entityTypeInput?.value || '';
      if (entityType) query.set('entity_type', entityType);
      const res = await apiFetch('/api/search?' + query.toString());
      const data = await res.json();
      if (!data.length) {
        entityList.innerHTML = '<div class="empty-state" style="padding:20px 0"><p>No entities found</p></div>';
        return;
      }
      entityList.innerHTML = data.map(e => `
        <div class="entity-card" data-id="${e.id}" data-name="${e.name}">
          <span class="entity-dot t-${e.type || 'unknown'}"></span>
          <div class="entity-info">
            <div class="entity-name">${e.name}</div>
            <div class="entity-type">${e.type || ''}</div>
            <div class="entity-id">${e.id}</div>
          </div>
        </div>
      `).join('');
      entityList.querySelectorAll('.entity-card').forEach(card => {
        card.addEventListener('click', () => selectEntity(card));
        card.addEventListener('dblclick', () => { selectEntity(card); fireVisualize(); });
      });
    } catch (e) {
      toast('Search failed', 'error');
    }
  }

  function selectEntity(card) {
    entityList.querySelectorAll('.entity-card').forEach(c => c.classList.remove('selected'));
    card.classList.add('selected');
    selectedEntity = { id: card.dataset.id, name: card.dataset.name };
    searchInput.value = card.dataset.name;
    if (entityIdInput) entityIdInput.value = card.dataset.id || '';
  }

  function fireVisualize() {
    const typedEntityId = entityIdInput?.value.trim() || '';
    const seedId = typedEntityId || selectedEntity?.id || null;
    const seed = selectedEntity?.name || searchInput.value.trim() || typedEntityId;
    if (!seed && !seedId) return;
    onVisualize({
      seed,
      seedId,
      depth: parseInt(document.getElementById('depthInput').value, 10),
      minConfidence: parseFloat(confInput.value),
      since: _toIsoDateTime(sinceInput?.value || ''),
      until: _toIsoDateTime(untilInput?.value || ''),
      timelineInterval: timelineIntervalInput?.value || 'month',
      showTimeline: timelineToggleInput?.checked ?? true,
    });
  }

  return {
    getConfidence: () => parseFloat(confInput.value),
    getDepth: () => parseInt(document.getElementById('depthInput').value, 10),
  };
}


function _toIsoDateTime(value) {
  if (!value) return null;
  const dt = new Date(value);
  if (Number.isNaN(dt.getTime())) return null;
  return dt.toISOString();
}
