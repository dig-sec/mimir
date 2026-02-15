/**
 * Multi-Search module – allows running parallel searches and overlaying
 * their subgraphs on the same visualization.
 */
export function initMultiSearch(loadGraphFn, renderGraphFn) {
  const searches = new Map(); // Map of search_id -> {seed, seedId, depth, minConf, subgraph, active}
  let nextSearchId = 0;

  const multiSearchPanel = document.getElementById('multiSearchPanel');
  const addSearchBtn = document.getElementById('addCurrentSearchBtn');
  const searchesListEl = document.getElementById('searchesList');
  const mergeViewBtn = document.getElementById('mergeViewBtn');

  if (!multiSearchPanel) return;

  /* ── add current search button ─── */
  addSearchBtn?.addEventListener('click', addCurrentSearch);

  /* ── merge view button ─── */
  mergeViewBtn?.addEventListener('click', mergeAllSearches);

  function addCurrentSearch() {
    const seedInput = document.getElementById('searchInput');
    const seedIdInput = document.getElementById('entityIdInput');
    const depthInput = document.getElementById('depthInput');
    const confInput = document.getElementById('confInput');

    const seed = seedInput?.value?.trim();
    const seedId = seedIdInput?.value?.trim();
    const depth = parseInt(depthInput?.value || 1, 10);
    const minConf = parseFloat(confInput?.value || 0);

    if (!seed && !seedId) {
      toast('Enter a search term or entity ID', 'error');
      return;
    }

    const searchId = nextSearchId++;
    const label = seed || seedId;
    searches.set(searchId, {
      label,
      seed,
      seedId,
      depth,
      minConf,
      subgraph: null,
      active: true,
    });

    renderSearchesList();
    toast(`Search added: ${label}`, 'success');
  }

  function renderSearchesList() {
    if (searches.size === 0) {
      searchesListEl.innerHTML = '<div class="empty-state" style="padding:10px 0"><p>No searches yet</p></div>';
      return;
    }

    searchesListEl.innerHTML = Array.from(searches.entries())
      .map(([id, s]) => `
        <div class="search-card" data-search-id="${id}">
          <div class="search-card-header">
            <span class="search-label">${esc(s.label)}</span>
            <span class="search-depth">depth: ${s.depth}</span>
          </div>
          <div class="search-card-controls">
            <label class="check-inline">
              <input type="checkbox" class="search-toggle" ${s.active ? 'checked' : ''} />
              <span>Show</span>
            </label>
            <button class="btn btn-sm btn-danger search-remove" title="Remove search">&times;</button>
          </div>
        </div>
      `)
      .join('');

    /* ── toggle search visibility ─── */
    searchesListEl.querySelectorAll('.search-toggle').forEach((chk, i) => {
      const id = Array.from(searches.keys())[i];
      chk.addEventListener('change', () => {
        const s = searches.get(id);
        s.active = chk.checked;
        mergeAllSearches();
      });
    });

    /* ── remove search ─── */
    searchesListEl.querySelectorAll('.search-remove').forEach((btn, i) => {
      btn.addEventListener('click', () => {
        const id = Array.from(searches.keys())[i];
        searches.delete(id);
        renderSearchesList();
        if (searches.size > 0) mergeAllSearches();
      });
    });
  }

  async function mergeAllSearches() {
    const activeSearches = Array.from(searches.values()).filter(s => s.active);
    if (!activeSearches.length) {
      toast('No active searches to merge', 'error');
      return;
    }

    mergeViewBtn.disabled = true;
    mergeViewBtn.textContent = 'Merging...';

    try {
      const merged = {
        nodes: {},
        edges: {},
      };

      // Load subgraph for each active search
      for (const search of activeSearches) {
        const payload = {
          depth: search.depth,
          min_confidence: search.minConf,
        };
        if (search.seedId) {
          payload.seed_id = search.seedId;
        } else {
          payload.seed_name = search.seed;
        }

        const res = await fetch(apiUrl('/query'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        if (!res.ok) continue;

        const subgraph = await res.json();
        search.subgraph = subgraph;

        // Merge nodes and edges
        for (const node of subgraph.nodes || []) {
          if (!merged.nodes[node.id]) {
            merged.nodes[node.id] = {
              id: node.id,
              name: node.name,
              type: node.type,
              searches: [search.label],
            };
          } else {
            merged.nodes[node.id].searches.push(search.label);
          }
        }

        for (const edge of subgraph.edges || []) {
          if (!merged.edges[edge.id]) {
            merged.edges[edge.id] = {
              ...edge,
              searches: [search.label],
            };
          } else {
            merged.edges[edge.id].searches.push(search.label);
          }
        }
      }

      // Render merged graph
      const payload = {
        nodes: Object.values(merged.nodes),
        edges: Object.values(merged.edges),
      };

      if (renderGraphFn) {
        renderGraphFn(payload);
        toast(
          `Merged ${activeSearches.length} search(es): ${activeSearches.map(s => s.label).join(', ')}`,
          'success'
        );
      }
    } catch (err) {
      toast(err.message || 'Merge failed', 'error');
    } finally {
      mergeViewBtn.disabled = false;
      mergeViewBtn.textContent = 'Merge Views';
    }
  }

  return {
    addSearch: addCurrentSearch,
    merge: mergeAllSearches,
    getSearches: () => searches,
  };
}

function apiUrl(path) {
  const base = window.__MIMIR_API_BASE__ || '';
  const normalized = base ? (base.endsWith('/') ? base.slice(0, -1) : base) : '';
  return normalized + path;
}

function esc(v) {
  return String(v ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function toast(msg, type) {
  const toasts = document.getElementById('toasts');
  if (!toasts) return;
  const el = document.createElement('div');
  el.className = `toast toast-${type}`;
  el.textContent = msg;
  toasts.appendChild(el);
  setTimeout(() => el.remove(), 3000);
}
