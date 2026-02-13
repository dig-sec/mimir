import { toast, apiFetch } from './helpers.js';

/* ── type icons (inline SVG fragments) ───────── */
const TYPE_ICONS = {
  malware:        '<svg class="pir-q-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2a5 5 0 0 1 5 5v3a5 5 0 0 1-10 0V7a5 5 0 0 1 5-5z"/><path d="M3 12h2m14 0h2M5.6 5.6l1.4 1.4m10 10 1.4 1.4M5.6 18.4l1.4-1.4m10-10 1.4-1.4M12 18v4"/></svg>',
  threat_actor:   '<svg class="pir-q-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 12a5 5 0 1 0 0-10 5 5 0 0 0 0 10zM20 21v-2a4 4 0 0 0-3-3.87M4 21v-2a4 4 0 0 1 3-3.87"/></svg>',
  vulnerability:  '<svg class="pir-q-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 9v4m0 4h.01M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/></svg>',
  attack_pattern: '<svg class="pir-q-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m2 4 3 12h14l3-12M6.7 16 4 22m13.3-6L20 22M6 4h12l-2 8H8z"/></svg>',
  infrastructure: '<svg class="pir-q-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><circle cx="6" cy="6" r="1"/><circle cx="6" cy="18" r="1"/></svg>',
};

export function initPIR() {
  const refreshBtn = document.getElementById('pirRefreshBtn');
  const dateFrom   = document.getElementById('pirDateFrom');
  const dateTo     = document.getElementById('pirDateTo');
  const topNInput  = document.getElementById('pirTopNInput');
  const list       = document.getElementById('pirList');
  if (!refreshBtn || !dateFrom || !dateTo || !topNInput || !list) return;

  /* Default range: last 7 days */
  const today = new Date();
  const weekAgo = new Date(today);
  weekAgo.setDate(today.getDate() - 7);
  dateTo.value = today.toISOString().slice(0, 10);
  dateFrom.value = weekAgo.toISOString().slice(0, 10);
  dateTo.max = today.toISOString().slice(0, 10);

  let loadedOnce = false;

  refreshBtn.addEventListener('click', () => void refreshTrending());

  /* Auto-refresh when inputs change */
  dateFrom.addEventListener('change', () => { if (loadedOnce) void refreshTrending(); });
  dateTo.addEventListener('change', () => { if (loadedOnce) void refreshTrending(); });
  topNInput.addEventListener('change', () => { if (loadedOnce) void refreshTrending(); });

  /* Auto-load on first tab visit */
  const pirTabBtn = document.querySelector('.tab-btn[data-tab="pir"]');
  if (pirTabBtn) {
    pirTabBtn.addEventListener('click', () => {
      if (!loadedOnce) void refreshTrending();
    });
  }

  /* ── fetch ─────────────────────────────── */
  async function refreshTrending() {
    /* Compute days from date range */
    const from = new Date(dateFrom.value);
    const to   = new Date(dateTo.value);
    const days = Math.max(1, Math.round((to - from) / 86400000));
    const topN = parseInt(topNInput.value, 10) || 10;

    refreshBtn.disabled = true;
    const skeleton = list.querySelector('.pir-skeleton');
    if (skeleton) skeleton.style.display = '';
    /* hide previous content but keep skeleton */
    list.querySelectorAll('.pir-question, .pir-banner, .empty-state').forEach(el => el.remove());

    try {
      const query = new URLSearchParams({ days: String(days), top_n: String(topN) });
      const res = await apiFetch('/api/pir/trending?' + query.toString());
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || 'PIR request failed');
      }
      const data = await res.json();
      renderTrending(data);
      loadedOnce = true;
      toast('PIR trends refreshed', 'success');
    } catch (err) {
      const message = err instanceof Error ? err.message : 'PIR request failed';
      if (skeleton) skeleton.style.display = 'none';
      list.innerHTML = `<div class="empty-state" style="padding:28px 0"><p>${escapeHtml(message)}</p></div>`;
      toast(message, 'error');
    } finally {
      refreshBtn.disabled = false;
    }
  }

  /* ── render ────────────────────────────── */
  function renderTrending(data) {
    const questions = Array.isArray(data?.questions) ? data.questions : [];

    if (!questions.length) {
      list.innerHTML = `<div class="empty-state" style="padding:28px 0"><p>No PIR data available for this window.</p></div>`;
      return;
    }

    const totalEntities = questions.reduce((s, q) => s + (q.items?.length || 0), 0);
    const windowLabel   = formatWindow(data.window);
    const generatedAt   = formatTimeAgo(data.generated_at);

    list.innerHTML = `
      <div class="pir-banner">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg>
        <div class="pir-banner-text">
          <strong>${totalEntities} trending entit${totalEntities === 1 ? 'y' : 'ies'} across ${questions.length} categories</strong>
          <span>${escapeHtml(windowLabel)} &middot; updated ${escapeHtml(generatedAt)}</span>
        </div>
      </div>
      <div class="pir-grid">
        ${questions.map(renderCard).join('')}
      </div>
    `;

    /* wire up clickable entity names */
    list.querySelectorAll('[data-entity-id]').forEach(el => {
      el.addEventListener('click', (e) => {
        e.stopPropagation();
        const entityId   = el.dataset.entityId;
        const entityName = el.dataset.entityName;
        if (!entityId) return;
        toggleDetail(el, entityId, entityName);
      });
    });
  }

  /* ── inline detail drawer ──────────────── */
  async function toggleDetail(itemEl, entityId, entityName) {
    /* if already open, close it */
    const existing = itemEl.nextElementSibling;
    if (existing?.classList.contains('pir-detail')) {
      existing.remove();
      itemEl.classList.remove('pir-item--active');
      return;
    }
    /* close any other open detail in same card */
    const card = itemEl.closest('.pir-card');
    card?.querySelectorAll('.pir-detail').forEach(d => d.remove());
    card?.querySelectorAll('.pir-item--active').forEach(i => i.classList.remove('pir-item--active'));

    itemEl.classList.add('pir-item--active');

    /* placeholder while loading */
    const drawer = document.createElement('div');
    drawer.className = 'pir-detail';
    drawer.innerHTML = `<div class="pir-detail-loading">Loading context for ${escapeHtml(entityName)}...</div>`;
    itemEl.insertAdjacentElement('afterend', drawer);

    try {
      const res = await apiFetch(`/api/pir/entity-context?entity_id=${encodeURIComponent(entityId)}`);
      if (!res.ok) throw new Error('Failed to load context');
      const data = await res.json();
      renderDetail(drawer, data, entityName);
    } catch (err) {
      drawer.innerHTML = `<div class="pir-detail-loading">${escapeHtml(err.message)}</div>`;
    }
  }

  function renderDetail(drawer, data, entityName) {
    const entity = data.entity || {};
    const attrs  = entity.attrs || {};
    const neighbors = data.neighbors || [];
    const sources   = data.sources || [];

    /* Build attribute pills (CVSS, exploit, etc.) */
    let attrHtml = '';
    if (attrs.cvss_score != null) {
      const severity = attrs.cvss_score >= 9 ? 'critical' : attrs.cvss_score >= 7 ? 'high' : attrs.cvss_score >= 4 ? 'medium' : 'low';
      attrHtml += `<span class="pir-detail-attr pir-cvss-${severity}">CVSS ${attrs.cvss_score}</span>`;
    }
    if (attrs.has_exploit === true)  attrHtml += `<span class="pir-detail-attr pir-attr-bad">Exploit Available</span>`;
    if (attrs.has_exploit === false) attrHtml += `<span class="pir-detail-attr pir-attr-ok">No Known Exploit</span>`;
    if (attrs.has_patch === true)    attrHtml += `<span class="pir-detail-attr pir-attr-ok">Patch Available</span>`;
    if (attrs.has_patch === false)   attrHtml += `<span class="pir-detail-attr pir-attr-bad">No Patch</span>`;
    if (attrs.mitre_id)              attrHtml += `<span class="pir-detail-attr">${escapeHtml(attrs.mitre_id)}</span>`;

    /* Group neighbors by predicate */
    const byPred = {};
    for (const n of neighbors) {
      if (n.type === 'report') continue; /* skip reports, we show source URLs instead */
      const key = n.predicate;
      if (!byPred[key]) byPred[key] = [];
      if (byPred[key].length < 6) byPred[key].push(n);
    }

    let neighborsHtml = '';
    for (const [pred, items] of Object.entries(byPred)) {
      const pills = items.map(n =>
        `<span class="pir-detail-entity t-${escapeAttr(n.type)}" data-entity-id="${escapeHtml(n.id)}" data-entity-name="${escapeHtml(n.name)}">
          <span class="entity-dot t-${escapeAttr(n.type)}"></span>${escapeHtml(n.name)}
        </span>`
      ).join('');
      neighborsHtml += `<div class="pir-detail-pred-group"><span class="pir-detail-pred-label">${escapeHtml(pred)}</span>${pills}</div>`;
    }

    /* Sources as clickable links */
    let sourcesHtml = '';
    if (sources.length) {
      const sourceItems = sources.slice(0, 10).map(s => {
        const url = s.uri;
        const title = s.title || (url.length > 70 ? url.substring(0, 67) + '...' : url);
        const timeAgo = s.timestamp ? formatTimeAgo(s.timestamp) : '';
        return `<a class="pir-detail-source" href="${escapeAttr(url)}" target="_blank" rel="noopener">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 01-2 2H5a2 2 0 01-2-2V8a2 2 0 012-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
          <span>${escapeHtml(title)}</span>
          ${timeAgo ? `<span class="pir-detail-time">${escapeHtml(timeAgo)}</span>` : ''}
        </a>`;
      }).join('');
      sourcesHtml = `<div class="pir-detail-section"><div class="pir-detail-section-title">Source Articles</div>${sourceItems}</div>`;
    }

    /* Action buttons */
    const actionsHtml = `
      <div class="pir-detail-actions">
        <button class="btn btn-sm btn-primary pir-detail-viz">Visualize in Graph</button>
      </div>
    `;

    drawer.innerHTML = `
      ${attrHtml ? `<div class="pir-detail-attrs">${attrHtml}</div>` : ''}
      ${neighborsHtml ? `<div class="pir-detail-section"><div class="pir-detail-section-title">Connected Entities</div>${neighborsHtml}</div>` : ''}
      ${sourcesHtml}
      ${actionsHtml}
    `;

    /* Wire up the visualize button */
    drawer.querySelector('.pir-detail-viz')?.addEventListener('click', (e) => {
      e.stopPropagation();
      const searchInput   = document.getElementById('searchInput');
      const entityIdInput = document.getElementById('entityIdInput');
      const vizBtn        = document.getElementById('vizBtn');
      if (searchInput) {
        document.querySelector('.tab-btn[data-tab="explore"]')?.click();
        searchInput.value = entityName;
        if (entityIdInput) entityIdInput.value = data.entity?.id || '';
        if (vizBtn) setTimeout(() => vizBtn.click(), 350);
      }
    });

    /* Wire up neighbor entity clicks → open their detail */
    drawer.querySelectorAll('.pir-detail-entity').forEach(el => {
      el.addEventListener('click', (e) => {
        e.stopPropagation();
        const searchInput   = document.getElementById('searchInput');
        const entityIdInput = document.getElementById('entityIdInput');
        const vizBtn        = document.getElementById('vizBtn');
        if (searchInput) {
          document.querySelector('.tab-btn[data-tab="explore"]')?.click();
          searchInput.value = el.dataset.entityName || '';
          if (entityIdInput) entityIdInput.value = el.dataset.entityId || '';
          if (vizBtn) setTimeout(() => vizBtn.click(), 350);
        }
      });
    });
  }

  function renderCard(question) {
    const items = Array.isArray(question?.items) ? question.items : [];
    const title = escapeHtml(question?.question || 'PIR Question');
    const type  = String(question?.entity_type || 'unknown');
    const icon  = TYPE_ICONS[type] || '';
    const maxEvidence = items.reduce((m, i) => Math.max(m, Number(i?.current_evidence || 0)), 1);

    return `
      <section class="pir-card">
        <div class="pir-card-head">
          <h3>${icon}${title}</h3>
          <span>
            <span class="pir-chip t-${escapeAttr(type)}">${escapeHtml(type.replace(/_/g, ' '))}</span>
            <span class="pir-count-badge">${items.length}</span>
          </span>
        </div>
        ${items.length
          ? `<div class="pir-items">${items.map((item, idx) => renderItem(item, idx, maxEvidence)).join('')}</div>`
          : '<div class="pir-empty">No trending entities in this window.</div>'
        }
      </section>`;
  }

  function renderItem(item, index, maxEvidence) {
    const delta      = Number(item?.delta_evidence || 0);
    const current    = Number(item?.current_evidence || 0);
    const previous   = Number(item?.previous_evidence || 0);
    const trendScore = Number(item?.trend_score || 0);
    const predicates = Array.isArray(item?.top_predicates) ? item.top_predicates : [];
    const type       = String(item?.type || 'unknown');
    const name       = item?.name || 'Unknown';
    const entityId   = item?.entity_id || '';

    /* trend badge */
    let trendClass, trendLabel;
    if (delta > 0) {
      trendClass = 'up';
      trendLabel = `▲ +${formatInt(delta)}`;
    } else if (delta < 0) {
      trendClass = 'down';
      trendLabel = `▼ ${formatInt(delta)}`;
    } else {
      trendClass = 'flat';
      trendLabel = '— 0';
    }

    /* bar width proportional to max */
    const barPct = maxEvidence ? Math.round((current / maxEvidence) * 100) : 0;
    const barColor = `var(--c-${type}, #94a3b8)`;

    return `
      <article class="pir-item" data-entity-id="${escapeHtml(entityId)}" data-entity-name="${escapeHtml(name)}">
        <span class="pir-item-rank">${index + 1}</span>
        <div class="pir-item-body">
          <div class="pir-item-title">
            <span class="entity-dot t-${escapeAttr(type)}"></span>
            <span class="pir-name">${escapeHtml(name)}</span>
          </div>
          <div class="pir-sparkrow">
            <span class="pir-evidence">${formatInt(current)} evidence (was ${formatInt(previous)})</span>
            <span class="pir-trend-badge ${trendClass}">${trendLabel}</span>
            <span class="pir-bar-track"><span class="pir-bar-fill" style="width:${barPct}%;background:${barColor}"></span></span>
          </div>
          ${predicates.length
            ? `<div class="pir-predicates">${predicates.map(p => `<span class="pir-pred">${escapeHtml(String(p.predicate))} ${formatInt(p.count)}</span>`).join('')}</div>`
            : ''
          }
        </div>
      </article>`;
  }
}

function formatInt(value) {
  const parsed = Number(value || 0);
  return Number.isFinite(parsed) ? Math.round(parsed).toLocaleString() : '0';
}

function formatTimeAgo(value) {
  const dt = new Date(value);
  if (Number.isNaN(dt.getTime())) return String(value || '');
  const diff = Date.now() - dt.getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return dt.toLocaleDateString();
}

function formatWindow(windowData) {
  const days = Number(windowData?.days || 0);
  const since = formatDate(windowData?.since);
  const until = formatDate(windowData?.until);
  if (!since && !until) return `${days || '?'} day window`;
  return `${days}d window (${since} – ${until})`;
}

function formatDate(value) {
  const dt = new Date(value);
  if (Number.isNaN(dt.getTime())) return String(value || '');
  return dt.toLocaleDateString();
}

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function escapeAttr(value) {
  return String(value).replace(/[^a-zA-Z0-9_-]/g, '_');
}
