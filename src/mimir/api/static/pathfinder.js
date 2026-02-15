import { toast, apiFetch } from './helpers.js';

/**
 * Path Finder module – provides shortest / all / longest path queries
 * between two entities in the knowledge graph.
 */
export function initPathFinder(renderGraphFn) {
  const toggle = document.getElementById('pathToggle');
  const content = document.getElementById('pathContent');

  const sourceInput = document.getElementById('pathSourceInput');
  const sourceIdEl = document.getElementById('pathSourceId');
  const sourceSuggestions = document.getElementById('pathSourceSuggestions');

  const targetInput = document.getElementById('pathTargetInput');
  const targetIdEl = document.getElementById('pathTargetId');
  const targetSuggestions = document.getElementById('pathTargetSuggestions');

  const algorithmSelect = document.getElementById('pathAlgorithm');
  const maxDepthInput = document.getElementById('pathMaxDepth');
  const confInput = document.getElementById('pathConfInput');
  const confVal = document.getElementById('pathConfVal');
  const findBtn = document.getElementById('findPathBtn');
  const resultDiv = document.getElementById('pathResult');
  const summaryDiv = document.getElementById('pathSummary');
  const listDiv = document.getElementById('pathList');

  if (!toggle || !content) return;

  /* ── collapse / expand ─── */
  toggle.addEventListener('click', () => {
    const open = content.style.display !== 'none';
    content.style.display = open ? 'none' : '';
    toggle.textContent = (open ? '\u25B6' : '\u25BC') + ' Path Finder';
  });

  /* ── confidence slider ─── */
  confInput?.addEventListener('input', () => {
    confVal.textContent = confInput.value;
  });

  /* ── entity autocomplete ─── */
  let sourceTimer, targetTimer;

  sourceInput.addEventListener('input', () => {
    sourceIdEl.value = '';
    clearTimeout(sourceTimer);
    const q = sourceInput.value.trim();
    if (!q) { sourceSuggestions.innerHTML = ''; sourceSuggestions.style.display = 'none'; return; }
    sourceTimer = setTimeout(() => searchEntities(q, sourceSuggestions, (id, name) => {
      sourceIdEl.value = id;
      sourceInput.value = name;
      sourceSuggestions.style.display = 'none';
    }), 250);
  });

  targetInput.addEventListener('input', () => {
    targetIdEl.value = '';
    clearTimeout(targetTimer);
    const q = targetInput.value.trim();
    if (!q) { targetSuggestions.innerHTML = ''; targetSuggestions.style.display = 'none'; return; }
    targetTimer = setTimeout(() => searchEntities(q, targetSuggestions, (id, name) => {
      targetIdEl.value = id;
      targetInput.value = name;
      targetSuggestions.style.display = 'none';
    }), 250);
  });

  /* close suggestions on outside click */
  document.addEventListener('click', (e) => {
    if (!sourceInput.contains(e.target) && !sourceSuggestions.contains(e.target)) {
      sourceSuggestions.style.display = 'none';
    }
    if (!targetInput.contains(e.target) && !targetSuggestions.contains(e.target)) {
      targetSuggestions.style.display = 'none';
    }
  });

  /* ── find path button ─── */
  findBtn.addEventListener('click', findPath);

  async function searchEntities(q, container, onSelect) {
    try {
      const res = await apiFetch('/api/search?' + new URLSearchParams({ q }));
      const data = await res.json();
      if (!data.length) {
        container.innerHTML = '<div class="path-no-match">No entities found</div>';
        container.style.display = '';
        return;
      }
      container.innerHTML = data.slice(0, 8).map(e => `
        <div class="path-suggestion-item" data-id="${esc(e.id)}" data-name="${esc(e.name)}">
          <span class="entity-dot t-${escAttr(e.type || 'unknown')}" style="flex-shrink:0"></span>
          <span class="path-sug-name">${esc(e.name)}</span>
          <span class="path-sug-type">${esc(e.type || '')}</span>
        </div>
      `).join('');
      container.style.display = '';
      container.querySelectorAll('.path-suggestion-item').forEach(item => {
        item.addEventListener('click', () => onSelect(item.dataset.id, item.dataset.name));
      });
    } catch {
      container.innerHTML = '';
      container.style.display = 'none';
    }
  }

  async function findPath() {
    const srcId = sourceIdEl.value;
    const srcName = sourceInput.value.trim();
    const tgtId = targetIdEl.value;
    const tgtName = targetInput.value.trim();

    if ((!srcId && !srcName) || (!tgtId && !tgtName)) {
      toast('Select both source and target entities', 'error');
      return;
    }

    const algorithm = algorithmSelect.value;
    const maxDepth = parseInt(maxDepthInput.value, 10) || 6;
    const minConf = parseFloat(confInput.value) || 0.0;

    findBtn.disabled = true;
    findBtn.textContent = 'Searching...';
    resultDiv.style.display = 'none';

    try {
      const params = new URLSearchParams({ min_confidence: minConf, max_depth: maxDepth });
      if (srcId) params.set('source_id', srcId); else params.set('source_name', srcName);
      if (tgtId) params.set('target_id', tgtId); else params.set('target_name', tgtName);

      const endpoint = `/path/${algorithm}`;
      const res = await apiFetch(endpoint + '?' + params.toString());
      if (!res.ok) {
        const e = await res.json();
        throw new Error(e.detail || 'Path query failed');
      }
      const data = await res.json();
      showPathResult(data, algorithm, renderGraphFn);
    } catch (e) {
      toast(e.message || 'Path query failed', 'error');
    } finally {
      findBtn.disabled = false;
      findBtn.textContent = 'Find Path';
    }
  }

  function showPathResult(data, algorithm, renderFn) {
    resultDiv.style.display = '';
    const count = data.paths.length;
    const algoLabel = { shortest: 'Shortest', all: 'All', longest: 'Longest' }[algorithm] || algorithm;

    if (!count) {
      summaryDiv.innerHTML = `<span class="path-no-result">No path found between these entities</span>`;
      listDiv.innerHTML = '';
      return;
    }

    summaryDiv.innerHTML = `<strong>${algoLabel}:</strong> ${count} path(s) found — <em>${esc(data.source.name)}</em> → <em>${esc(data.target.name)}</em>`;

    listDiv.innerHTML = data.paths.map((p, i) => {
      const hops = p.length || p.edges.length;
      const nodeNames = p.nodes.map(n => `<span class="path-node">${esc(n.name)}</span>`);
      const edgeLabels = p.edges.map(e => `<span class="path-edge">${esc(e.predicate)}</span>`);
      let chain = '';
      for (let j = 0; j < nodeNames.length; j++) {
        chain += nodeNames[j];
        if (j < edgeLabels.length) chain += ' <span class="path-arrow">→</span> ' + edgeLabels[j] + ' <span class="path-arrow">→</span> ';
      }
      return `
        <div class="path-card" data-path-idx="${i}">
          <div class="path-card-header">Path ${i + 1} <span class="path-hops">(${hops} hop${hops !== 1 ? 's' : ''})</span></div>
          <div class="path-chain">${chain}</div>
        </div>`;
    }).join('');

    /* clicking a path renders it in the graph */
    listDiv.querySelectorAll('.path-card').forEach(card => {
      card.addEventListener('click', () => {
        const idx = parseInt(card.dataset.pathIdx, 10);
        const path = data.paths[idx];
        if (path && renderFn) {
          renderFn({
            nodes: path.nodes,
            edges: path.edges,
          });
        }
      });
    });

    /* Auto-render the first/only path */
    if (data.paths.length && renderFn) {
      // Merge all paths into a single graph for display
      const allNodes = {};
      const allEdges = {};
      for (const p of data.paths) {
        for (const n of p.nodes) allNodes[n.id] = n;
        for (const e of p.edges) allEdges[e.id] = e;
      }
      renderFn({
        nodes: Object.values(allNodes),
        edges: Object.values(allEdges),
      });
    }
  }
}


function esc(v) {
  return String(v ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function escAttr(v) {
  return String(v ?? '').replace(/[^a-zA-Z0-9_-]/g, '_');
}
