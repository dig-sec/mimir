import { toast, apiFetch } from './helpers.js';

/* ── type icons (inline SVG fragments) ───────── */
const TYPE_ICONS = {
  malware:        '<svg class="pir-q-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2a5 5 0 0 1 5 5v3a5 5 0 0 1-10 0V7a5 5 0 0 1 5-5z"/><path d="M3 12h2m14 0h2M5.6 5.6l1.4 1.4m10 10 1.4 1.4M5.6 18.4l1.4-1.4m10-10 1.4-1.4M12 18v4"/></svg>',
  threat_actor:   '<svg class="pir-q-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 12a5 5 0 1 0 0-10 5 5 0 0 0 0 10zM20 21v-2a4 4 0 0 0-3-3.87M4 21v-2a4 4 0 0 1 3-3.87"/></svg>',
  vulnerability:  '<svg class="pir-q-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 9v4m0 4h.01M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/></svg>',
  attack_pattern: '<svg class="pir-q-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m2 4 3 12h14l3-12M6.7 16 4 22m13.3-6L20 22M6 4h12l-2 8H8z"/></svg>',
  infrastructure: '<svg class="pir-q-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><circle cx="6" cy="6" r="1"/><circle cx="6" cy="18" r="1"/></svg>',
};

/* ── palette for individual entity lines within a card ─── */
const LINE_PALETTE = [
  '#2563eb', '#dc2626', '#16a34a', '#ea580c', '#9333ea',
  '#0891b2', '#ca8a04', '#be185d', '#4f46e5', '#059669',
];

export function initPIR() {
  const refreshBtn = document.getElementById('pirRefreshBtn');
  const dateFrom   = document.getElementById('pirDateFrom');
  const dateTo     = document.getElementById('pirDateTo');
  const topNInput  = document.getElementById('pirTopNInput');
  const list       = document.getElementById('pirList');
  if (!refreshBtn || !dateFrom || !dateTo || !topNInput || !list) return;

  /* Default range: last 30 days */
  const today = new Date();
  const monthAgo = new Date(today);
  monthAgo.setDate(today.getDate() - 30);
  dateTo.value = today.toISOString().slice(0, 10);
  dateFrom.value = monthAgo.toISOString().slice(0, 10);
  dateTo.max = today.toISOString().slice(0, 10);

  let loadedOnce = false;

  refreshBtn.addEventListener('click', () => void refreshTrending());

  dateFrom.addEventListener('change', () => { if (loadedOnce) void refreshTrending(); });
  dateTo.addEventListener('change',   () => { if (loadedOnce) void refreshTrending(); });
  topNInput.addEventListener('change', () => { if (loadedOnce) void refreshTrending(); });

  const pirTabBtn = document.querySelector('.tab-btn[data-tab="pir"]');
  if (pirTabBtn) {
    pirTabBtn.addEventListener('click', () => {
      if (!loadedOnce) void refreshTrending();
    });
  }

  /* ── fetch ─────────────────────────────── */
  async function refreshTrending() {
    const sinceStr = dateFrom.value;
    const untilStr = dateTo.value;
    const topN = parseInt(topNInput.value, 10) || 10;

    refreshBtn.disabled = true;
    const skeleton = list.querySelector('.pir-skeleton');
    if (skeleton) skeleton.style.display = '';
    list.querySelectorAll('.pir-question, .pir-banner, .empty-state, .pir-grid').forEach(el => el.remove());

    try {
      const query = new URLSearchParams({ since: sinceStr, until: untilStr, top_n: String(topN) });
      const res = await apiFetch('/api/pir/trending?' + query.toString());
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || 'PIR request failed');
      }
      const data = await res.json();
      renderPage(data);
      loadedOnce = true;
      toast('PIR trends refreshed', 'success');
    } catch (err) {
      const message = err instanceof Error ? err.message : 'PIR request failed';
      if (skeleton) skeleton.style.display = 'none';
      list.innerHTML = '<div class="empty-state" style="padding:28px 0"><p>' + esc(message) + '</p></div>';
      toast(message, 'error');
    } finally {
      refreshBtn.disabled = false;
    }
  }

  /* ── render full page ──────────────────── */
  function renderPage(data) {
    const questions = Array.isArray(data?.questions) ? data.questions : [];
    if (!questions.length) {
      list.innerHTML = '<div class="empty-state" style="padding:28px 0"><p>No PIR data available for this window.</p></div>';
      return;
    }

    const totalEntities = questions.reduce((s, q) => s + (q.items?.length || 0), 0);

    list.innerHTML =
      '<div class="pir-banner">' +
        '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg>' +
        '<div class="pir-banner-text">' +
          '<strong>' + totalEntities + ' trending entit' + (totalEntities === 1 ? 'y' : 'ies') + ' across ' + questions.length + ' categories</strong>' +
          '<span>' + esc(fmtWindow(data.window)) + ' &middot; updated ' + esc(fmtAgo(data.generated_at)) + '</span>' +
        '</div>' +
      '</div>' +
      '<div class="pir-grid">' + questions.map(q => renderCard(q)).join('') + '</div>';

    /* Render SVG charts after DOM is ready */
    const cards = list.querySelectorAll('.pir-card[data-pir-type]');
    cards.forEach((card, ci) => {
      const q = questions[ci];
      if (!q || !q.items?.length) return;
      const chartEl  = card.querySelector('[data-pir-chart]');
      const legendEl = card.querySelector('[data-pir-legend]');
      if (chartEl) renderPIRChart(chartEl, legendEl, q);
    });

    wireInteractions();
  }

  /* ── render one PIR card ───────────────── */
  function renderCard(question) {
    const items = Array.isArray(question?.items) ? question.items : [];
    const title = esc(question?.question || 'PIR Question');
    const type  = String(question?.entity_type || 'unknown');
    const icon  = TYPE_ICONS[type] || '';

    /* Aggregate stats */
    const aggDaily = {};
    for (const item of items) {
      for (const h of (item.history || [])) {
        aggDaily[h.bucket_start] = (aggDaily[h.bucket_start] || 0) + (h.evidence_count || 0);
      }
    }
    const dayKeys   = Object.keys(aggDaily).sort();
    const aggValues = dayKeys.map(d => aggDaily[d]);
    const totalEvidence = aggValues.reduce((s, v) => s + v, 0);

    let aggTrendHtml = '';
    if (dayKeys.length >= 4) {
      const half = Math.floor(dayKeys.length / 2);
      const first  = aggValues.slice(0, half).reduce((s, v) => s + v, 0);
      const second = aggValues.slice(half).reduce((s, v) => s + v, 0);
      const diff = second - first;
      if (diff > 0) aggTrendHtml = '<span class="pir-trend-badge up">&#9650; +' + fmtInt(diff) + '</span>';
      else if (diff < 0) aggTrendHtml = '<span class="pir-trend-badge down">&#9660; ' + fmtInt(diff) + '</span>';
      else aggTrendHtml = '<span class="pir-trend-badge flat">&mdash; 0</span>';
    }

    return (
      '<section class="pir-card" data-pir-type="' + escAttr(type) + '">' +
        '<div class="pir-card-head">' +
          '<h3>' + icon + title + '</h3>' +
          '<span>' +
            '<span class="pir-chip t-' + escAttr(type) + '">' + esc(type.replace(/_/g, ' ')) + '</span>' +
            '<span class="pir-count-badge">' + items.length + '</span>' +
          '</span>' +
        '</div>' +
        (items.length ? (
          '<div class="pir-card-stats">' +
            '<span class="pir-stat-total">' + fmtInt(totalEvidence) + ' total evidence &middot; ' + dayKeys.length + ' days</span>' +
            aggTrendHtml +
          '</div>' +
          '<div class="pir-card-chart" data-pir-chart="' + escAttr(type) + '"></div>' +
          '<div class="pir-card-legend" data-pir-legend="' + escAttr(type) + '"></div>' +
          '<div class="pir-items" data-pir-items="' + escAttr(type) + '">' +
            items.map((item, idx) => renderItem(item, idx)).join('') +
          '</div>'
        ) : '<div class="pir-empty">No trending entities in this window.</div>') +
      '</section>'
    );
  }

  /* ── render one entity row ─────────────── */
  function renderItem(item, index) {
    const delta   = Number(item?.delta_evidence || 0);
    const current = Number(item?.current_evidence || 0);
    const prev    = Number(item?.previous_evidence || 0);
    const type    = String(item?.type || 'unknown');
    const name    = item?.name || 'Unknown';
    const entityId = item?.entity_id || '';
    const color   = LINE_PALETTE[index % LINE_PALETTE.length];
    const preds   = Array.isArray(item?.top_predicates) ? item.top_predicates : [];

    let trendClass, trendLabel;
    if (delta > 0)       { trendClass = 'up';   trendLabel = '&#9650; +' + fmtInt(delta); }
    else if (delta < 0)  { trendClass = 'down'; trendLabel = '&#9660; '  + fmtInt(delta); }
    else                 { trendClass = 'flat'; trendLabel = '&mdash; 0'; }

    return (
      '<article class="pir-item" data-entity-id="' + esc(entityId) + '" data-entity-name="' + esc(name) + '" data-entity-type="' + escAttr(type) + '">' +
        '<span class="pir-item-color" style="background:' + color + '"></span>' +
        '<div class="pir-item-body">' +
          '<div class="pir-item-title">' +
            '<span class="pir-name">' + esc(name) + '</span>' +
            '<span class="pir-trend-badge sm ' + trendClass + '">' + trendLabel + '</span>' +
          '</div>' +
          '<div class="pir-item-meta">' +
            '<span>' + fmtInt(current) + ' evidence</span>' +
            '<span class="pir-item-sep">&middot;</span>' +
            '<span>was ' + fmtInt(prev) + '</span>' +
            (preds.length
              ? '<span class="pir-item-sep">&middot;</span><span>' + preds.slice(0,2).map(p => esc(p.predicate)).join(', ') + '</span>'
              : '') +
          '</div>' +
        '</div>' +
      '</article>'
    );
  }

  /* ── wire interactions ─────────────────── */
  function wireInteractions() {
    list.querySelectorAll('.pir-item[data-entity-id]').forEach(el => {
      el.addEventListener('click', (e) => {
        e.stopPropagation();
        toggleDetail(el, el.dataset.entityId, el.dataset.entityName);
      });
    });
  }

  /* ── render multi-line SVG chart per PIR card ── */
  function renderPIRChart(chartEl, legendEl, question) {
    const items = question.items || [];
    if (!items.length) { chartEl.innerHTML = '<div class="pir-chart-empty">No data</div>'; return; }

    const daySet = new Set();
    for (const item of items) {
      for (const h of (item.history || [])) daySet.add(h.bucket_start);
    }
    const dayKeys = [...daySet].sort();
    if (!dayKeys.length) { chartEl.innerHTML = '<div class="pir-chart-empty">No history data</div>'; return; }

    /* Per-item daily maps */
    const series = items.slice(0, 10).map((item, idx) => {
      const daily = {};
      for (const h of (item.history || [])) daily[h.bucket_start] = h.evidence_count || 0;
      return { name: item.name || 'Unknown', color: LINE_PALETTE[idx % LINE_PALETTE.length], daily, total: item.current_evidence || 0 };
    });

    /* Aggregate per day */
    const aggDaily = {};
    for (const item of items) {
      for (const h of (item.history || [])) aggDaily[h.bucket_start] = (aggDaily[h.bucket_start] || 0) + (h.evidence_count || 0);
    }

    /* Dimensions */
    const margin = { top: 16, right: 16, bottom: 60, left: 44 };
    const chartWidth = Math.max(700, chartEl.clientWidth || 800);
    const chartHeight = 250;
    const w = chartWidth - margin.left - margin.right;
    const h = chartHeight - margin.top - margin.bottom;

    let maxVal = 1;
    for (const dk of dayKeys) {
      const agg = aggDaily[dk] || 0;
      if (agg > maxVal) maxVal = agg;
    }
    maxVal = Math.ceil(maxVal * 1.15) || 1;

    const xStep = dayKeys.length > 1 ? w / (dayKeys.length - 1) : 0;

    /* Aggregate area */
    const aggPts = dayKeys.map((dk, i) => {
      const x = margin.left + i * xStep;
      const v = aggDaily[dk] || 0;
      const y = margin.top + h - (v / maxVal) * h;
      return { x, y };
    });
    const areaPath = 'M' + margin.left + ',' + (margin.top + h) + ' ' +
      aggPts.map(p => 'L' + p.x.toFixed(1) + ',' + p.y.toFixed(1)).join(' ') +
      ' L' + (margin.left + (dayKeys.length - 1) * xStep).toFixed(1) + ',' + (margin.top + h) + ' Z';
    const aggLine = aggPts.map(p => p.x.toFixed(1) + ',' + p.y.toFixed(1)).join(' ');

    /* Entity lines */
    let linesHtml = '';
    let dotsHtml = '';
    for (const s of series) {
      const pts = [];
      for (let i = 0; i < dayKeys.length; i++) {
        const x = margin.left + i * xStep;
        const v = s.daily[dayKeys[i]] || 0;
        const y = margin.top + h - (v / maxVal) * h;
        pts.push(x.toFixed(1) + ',' + y.toFixed(1));
        if (v > 0) {
          dotsHtml += '<circle cx="' + x.toFixed(1) + '" cy="' + y.toFixed(1) + '" r="2.5" fill="' + s.color + '" opacity="0.7">' +
            '<title>' + esc(s.name) + ': ' + v + ' on ' + dayKeys[i] + '</title></circle>';
        }
      }
      linesHtml += '<polyline points="' + pts.join(' ') + '" fill="none" stroke="' + s.color + '" stroke-width="2" stroke-linejoin="round" opacity="0.85"/>';
    }

    /* Axes */
    let xLabels = '';
    const tickInt = Math.max(1, Math.floor(dayKeys.length / 5));
    for (let i = 0; i < dayKeys.length; i += tickInt) {
      const x = margin.left + i * xStep;
      xLabels += '<g transform="translate(' + x + ',' + (margin.top + h + 8) + ') rotate(45)">';
      xLabels += '<text x="0" y="0" text-anchor="start" fill="#94a3b8" font-size="11" font-family="monospace">' + dayKeys[i].slice(5) + '</text>';
      xLabels += '</g>';
      xLabels += '<line x1="' + x + '" y1="' + margin.top + '" x2="' + x + '" y2="' + (margin.top + h) + '" stroke="#f1f5f9" stroke-width="1"/>';
    }
    let yLabels = '';
    for (let i = 0; i <= 4; i++) {
      const val = Math.round(maxVal * (i / 4));
      const y = margin.top + h - (i / 4) * h;
      yLabels += '<text x="' + (margin.left - 6) + '" y="' + (y + 3) + '" text-anchor="end" fill="#94a3b8" font-size="10">' + val + '</text>';
      yLabels += '<line x1="' + margin.left + '" y1="' + y + '" x2="' + (margin.left + w) + '" y2="' + y + '" stroke="#f1f5f9" stroke-width="1"/>';
    }

    chartEl.innerHTML =
      '<svg width="100%" height="' + chartHeight + '" viewBox="0 0 ' + chartWidth + ' ' + chartHeight + '" preserveAspectRatio="xMidYMid meet">' +
        yLabels + xLabels +
        '<path d="' + areaPath + '" fill="#e0e7ff" opacity="0.3"/>' +
        '<polyline points="' + aggLine + '" fill="none" stroke="#a5b4fc" stroke-width="1.5" stroke-dasharray="4 3" opacity="0.5"/>' +
        '<line x1="' + margin.left + '" y1="' + (margin.top + h) + '" x2="' + (margin.left + w) + '" y2="' + (margin.top + h) + '" stroke="#e2e8f0" stroke-width="1"/>' +
        '<line x1="' + margin.left + '" y1="' + margin.top + '" x2="' + margin.left + '" y2="' + (margin.top + h) + '" stroke="#e2e8f0" stroke-width="1"/>' +
        linesHtml + dotsHtml +
      '</svg>';

    /* Legend */
    if (legendEl) {
      const aggTotal = Object.values(aggDaily).reduce((s, v) => s + v, 0);
      legendEl.innerHTML =
        '<span class="pir-legend-item pir-legend-agg">' +
          '<span class="pir-legend-line"></span>Total (' + fmtInt(aggTotal) + ')' +
        '</span>' +
        series.map(s =>
          '<span class="pir-legend-item">' +
            '<span class="pir-legend-dot" style="background:' + s.color + '"></span>' +
            esc(s.name) + ' (' + fmtInt(s.total) + ')' +
          '</span>'
        ).join('');
    }
  }

  /* ── detail drawer ─────────────────────── */
  async function toggleDetail(itemEl, entityId, entityName) {
    const existing = itemEl.nextElementSibling;
    if (existing?.classList.contains('pir-detail')) {
      existing.remove();
      itemEl.classList.remove('pir-item--active');
      return;
    }
    const card = itemEl.closest('.pir-card');
    card?.querySelectorAll('.pir-detail').forEach(d => d.remove());
    card?.querySelectorAll('.pir-item--active').forEach(i => i.classList.remove('pir-item--active'));
    itemEl.classList.add('pir-item--active');

    const drawer = document.createElement('div');
    drawer.className = 'pir-detail';
    drawer.innerHTML = '<div class="pir-detail-loading">Loading context for ' + esc(entityName) + '...</div>';
    itemEl.insertAdjacentElement('afterend', drawer);

    try {
      const ctxParams = new URLSearchParams({ entity_id: entityId });
      if (dateFrom.value) ctxParams.set('since', dateFrom.value);
      if (dateTo.value)   ctxParams.set('until', dateTo.value);
      const res = await apiFetch('/api/pir/entity-context?' + ctxParams.toString());
      if (!res.ok) throw new Error('Failed to load context');
      const data = await res.json();
      renderDetail(drawer, data, entityName, entityId);
    } catch (err) {
      drawer.innerHTML = '<div class="pir-detail-loading">' + esc(err.message) + '</div>';
    }
  }

  function renderDetail(drawer, data, entityName, entityId) {
    const entity    = data.entity || {};
    const attrs     = entity.attrs || {};
    const neighbors = data.neighbors || [];
    const sources   = data.sources || [];

    let attrHtml = '';
    if (attrs.cvss_score != null) {
      const sev = attrs.cvss_score >= 9 ? 'critical' : attrs.cvss_score >= 7 ? 'high' : attrs.cvss_score >= 4 ? 'medium' : 'low';
      attrHtml += '<span class="pir-detail-attr pir-cvss-' + sev + '">CVSS ' + attrs.cvss_score + '</span>';
    }
    if (attrs.has_exploit === true)  attrHtml += '<span class="pir-detail-attr pir-attr-bad">Exploit Available</span>';
    if (attrs.has_exploit === false) attrHtml += '<span class="pir-detail-attr pir-attr-ok">No Known Exploit</span>';
    if (attrs.has_patch === true)    attrHtml += '<span class="pir-detail-attr pir-attr-ok">Patch Available</span>';
    if (attrs.has_patch === false)   attrHtml += '<span class="pir-detail-attr pir-attr-bad">No Patch</span>';
    if (attrs.mitre_id)              attrHtml += '<span class="pir-detail-attr">' + esc(attrs.mitre_id) + '</span>';

    const byPred = {};
    for (const n of neighbors) {
      if (n.type === 'report') continue;
      if (!byPred[n.predicate]) byPred[n.predicate] = [];
      if (byPred[n.predicate].length < 6) byPred[n.predicate].push(n);
    }

    let neighborsHtml = '';
    for (const [pred, items] of Object.entries(byPred)) {
      const pills = items.map(n =>
        '<span class="pir-detail-entity t-' + escAttr(n.type) + '" data-entity-id="' + esc(n.id) + '" data-entity-name="' + esc(n.name) + '">' +
          '<span class="entity-dot t-' + escAttr(n.type) + '"></span>' + esc(n.name) +
        '</span>'
      ).join('');
      neighborsHtml += '<div class="pir-detail-pred-group"><span class="pir-detail-pred-label">' + esc(pred) + '</span>' + pills + '</div>';
    }

    let sourcesHtml = '';
    if (sources.length) {
      const si = sources.slice(0, 10).map(s => {
        const url = s.uri;
        const t = s.title || (url.length > 70 ? url.substring(0, 67) + '...' : url);
        const ta = s.timestamp ? fmtAgo(s.timestamp) : '';
        return '<a class="pir-detail-source" href="' + escAttr(url) + '" target="_blank" rel="noopener">' +
          '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 01-2 2H5a2 2 0 01-2-2V8a2 2 0 012-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>' +
          '<span>' + esc(t) + '</span>' +
          (ta ? '<span class="pir-detail-time">' + esc(ta) + '</span>' : '') +
        '</a>';
      }).join('');
      sourcesHtml = '<div class="pir-detail-section"><div class="pir-detail-section-title">Source Articles</div>' + si + '</div>';
    }

    drawer.innerHTML =
      (attrHtml ? '<div class="pir-detail-attrs">' + attrHtml + '</div>' : '') +
      (neighborsHtml ? '<div class="pir-detail-section"><div class="pir-detail-section-title">Connected Entities</div>' + neighborsHtml + '</div>' : '') +
      sourcesHtml +
      '<div class="pir-detail-actions">' +
        '<button class="btn btn-sm btn-primary pir-detail-viz">Visualize in Graph</button>' +
      '</div>';

    drawer.querySelector('.pir-detail-viz')?.addEventListener('click', (e) => {
      e.stopPropagation();
      const si2 = document.getElementById('searchInput');
      const eid = document.getElementById('entityIdInput');
      const vb  = document.getElementById('vizBtn');
      if (si2) {
        document.querySelector('.tab-btn[data-tab="explore"]')?.click();
        si2.value = entityName;
        if (eid) eid.value = data.entity?.id || '';
        if (vb) setTimeout(() => vb.click(), 350);
      }
    });

    drawer.querySelectorAll('.pir-detail-entity').forEach(el => {
      el.addEventListener('click', (e) => {
        e.stopPropagation();
        const si3 = document.getElementById('searchInput');
        const eid2 = document.getElementById('entityIdInput');
        const vb2  = document.getElementById('vizBtn');
        if (si3) {
          document.querySelector('.tab-btn[data-tab="explore"]')?.click();
          si3.value = el.dataset.entityName || '';
          if (eid2) eid2.value = el.dataset.entityId || '';
          if (vb2) setTimeout(() => vb2.click(), 350);
        }
      });
    });
  }
}

/* ── helpers ──────────────────────────────── */
function fmtInt(v) { const n = Number(v || 0); return Number.isFinite(n) ? Math.round(n).toLocaleString() : '0'; }
function fmtAgo(v) {
  const dt = new Date(v); if (Number.isNaN(dt.getTime())) return String(v || '');
  const m = Math.floor((Date.now() - dt.getTime()) / 60000);
  if (m < 1) return 'just now'; if (m < 60) return m + 'm ago';
  const h = Math.floor(m / 60); if (h < 24) return h + 'h ago';
  return dt.toLocaleDateString();
}
function fmtWindow(w) {
  const d = Number(w?.days || 0), s = fmtDate(w?.since), u = fmtDate(w?.until);
  return (!s && !u) ? (d || '?') + ' day window' : d + 'd window (' + s + ' \u2013 ' + u + ')';
}
function fmtDate(v) { const dt = new Date(v); return Number.isNaN(dt.getTime()) ? String(v || '') : dt.toLocaleDateString(); }
function esc(v) { return String(v).replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;').replaceAll("'",'&#39;'); }
function escAttr(v) { return String(v).replace(/[^a-zA-Z0-9_-]/g, '_'); }
