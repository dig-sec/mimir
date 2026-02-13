import { toast, apiFetch } from './helpers.js';

let graphData = null;
let sim = null;
let zoomBehavior = null;
let svg = null;
let g = null;
let ctxNode = null;
let getConf = () => 0;
let selectMode = false;
const selected = { nodes: new Set(), edges: new Set() };
let timelineData = null;
let lastGraphQuery = null;

/* entity type → color */
const TYPE_COLORS = {
  malware: '#ef4444',
  threat_actor: '#f97316',
  attack_pattern: '#a855f7',
  tool: '#3b82f6',
  vulnerability: '#eab308',
  campaign: '#ec4899',
  indicator: '#14b8a6',
  infrastructure: '#6366f1',
  mitigation: '#22c55e',
  report: '#64748b',
  identity: '#0ea5e9',
};
function nodeColor(d) { return TYPE_COLORS[d.type] || '#9ca3af'; }

function readDateInput(id) {
  const el = document.getElementById(id);
  if (!el || !el.value) return null;
  const dt = new Date(el.value);
  if (Number.isNaN(dt.getTime())) return null;
  return dt.toISOString();
}

function currentTemporalFilters() {
  return {
    since: readDateInput('sinceInput'),
    until: readDateInput('untilInput'),
  };
}

function timelineEnabled() {
  const input = document.getElementById('timelineToggle');
  return input ? input.checked : true;
}

function currentTimelineInterval() {
  const select = document.getElementById('timelineInterval');
  return select?.value || 'month';
}

export function initGraph(getConfidence) {
  getConf = getConfidence;

  document.getElementById('zoomInBtn').addEventListener('click', () => {
    if (svg) svg.transition().duration(300).call(zoomBehavior.scaleBy, 1.4);
  });
  document.getElementById('zoomOutBtn').addEventListener('click', () => {
    if (svg) svg.transition().duration(300).call(zoomBehavior.scaleBy, 0.7);
  });
  document.getElementById('fitBtn').addEventListener('click', fitToView);
  document.getElementById('pinBtn').addEventListener('click', togglePinAll);
  document.getElementById('clearGraphBtn').addEventListener('click', clearGraph);

  // ── Select mode ──
  const selectModeBtn = document.getElementById('selectModeBtn');
  const deleteSelectedBtn = document.getElementById('deleteSelectedBtn');

  selectModeBtn.addEventListener('click', () => {
    selectMode = !selectMode;
    selectModeBtn.classList.toggle('active', selectMode);
    if (!selectMode) clearSelection();
    // swap zoom vs lasso behaviour on the svg
    if (svg) {
      if (selectMode) {
        svg.on('.zoom', null);            // disable pan/zoom
        svg.call(lassoDrag);              // enable lasso
        svg.style('cursor', 'crosshair');
      } else {
        svg.on('.drag', null);            // remove lasso
        svg.call(zoomBehavior);           // restore pan/zoom
        svg.style('cursor', null);
      }
    }
  });

  deleteSelectedBtn.addEventListener('click', () => {
    if (selected.nodes.size === 0 && selected.edges.size === 0) return;
    const nBefore = graphData.nodes.length;
    const eBefore = graphData.edges.length;
    // remove selected nodes + any edges that connect to them
    graphData.nodes = graphData.nodes.filter(n => !selected.nodes.has(n.id));
    const removedNodeIds = selected.nodes;
    graphData.edges = graphData.edges.filter(e =>
      !selected.edges.has(e.id) &&
      !removedNodeIds.has(e.subject_id) &&
      !removedNodeIds.has(e.object_id)
    );
    const nRemoved = nBefore - graphData.nodes.length;
    const eRemoved = eBefore - graphData.edges.length;
    clearSelection();
    renderGraph(graphData);
    toast(`Removed ${nRemoved} node(s), ${eRemoved} edge(s)`, 'success');
  });

  // ── Export dropdown ──
  const exportBtn = document.getElementById('exportBtn');
  const exportMenu = document.getElementById('exportMenu');
  exportBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    exportMenu.classList.toggle('open');
  });
  document.addEventListener('click', () => exportMenu.classList.remove('open'));
  exportMenu.addEventListener('click', (e) => {
    e.stopPropagation();
  });
  document.querySelectorAll('.export-item').forEach(item => {
    item.addEventListener('click', () => {
      const fmt = item.dataset.format;
      exportMenu.classList.remove('open');
      doExport(fmt);
    });
  });

  // context menu actions
  document.getElementById('ctxExpand').addEventListener('click', () => {
    if (ctxNode) expandNode(ctxNode);
    hideCtxMenu();
  });
  document.getElementById('ctxPin').addEventListener('click', () => {
    if (ctxNode) togglePin(ctxNode);
    hideCtxMenu();
  });
  document.getElementById('ctxExplain').addEventListener('click', async () => {
    if (!ctxNode) return;
    hideCtxMenu();
    try {
      const res = await apiFetch('/explain?entity_id=' + encodeURIComponent(ctxNode.id));
      const data = await res.json();
      const n = data.relations?.length || 0;
      toast(`${ctxNode.name}: ${n} relation(s) with provenance`, 'success');
    } catch (e) {
      toast('Could not load provenance', 'error');
    }
  });
  document.getElementById('ctxRemove').addEventListener('click', () => {
    if (ctxNode) removeNode(ctxNode.id);
    hideCtxMenu();
  });

  // ── Export handler ──
  async function doExport(format) {
    if (!graphData || !graphData.nodes.length) {
      toast('Load a graph first', 'error');
      return;
    }
    // Send the currently visible graph to the server for conversion
    const payload = {
      nodes: graphData.nodes.map(n => ({ id: n.id, name: n.name, type: n.type })),
      edges: graphData.edges.map(e => ({
        id: e.id, subject_id: e.subject_id, predicate: e.predicate,
        object_id: e.object_id, confidence: e.confidence, attrs: e.attrs || {},
      })),
    };

    const EXT = { stix: 'json', json: 'json', csv: 'zip', graphml: 'graphml', markdown: 'md' };
    const ext = EXT[format] || 'json';

    try {
      toast(`Exporting ${format.toUpperCase()} (${payload.nodes.length} nodes)…`, 'success');
      const res = await apiFetch(`/api/export/${format}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || 'Export failed');
      }

      let blob;
      if (format === 'json' || format === 'stix') {
        const data = await res.json();
        blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      } else {
        blob = await res.blob();
      }

      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `wellspring-${format}-${new Date().toISOString().slice(0,10)}.${ext}`;
      a.click();
      URL.revokeObjectURL(a.href);
      toast(`${format.toUpperCase()} export downloaded`, 'success');
    } catch (e) {
      toast(e.message, 'error');
    }
  }

  window.addEventListener('resize', () => {
    if (svg) {
      const area = document.getElementById('graphArea');
      svg.attr('width', area.clientWidth).attr('height', area.clientHeight);
    }
    if (timelineData) renderTimeline(timelineData);
  });
}

/* ── public: load query and render ─────── */
export async function loadGraph(params, depthArg, minConfArg) {
  const seedName = typeof params === 'string' ? params : params.seed;
  const seedId = typeof params === 'string' ? null : (params.seedId || null);
  const depth = typeof params === 'string' ? depthArg : params.depth;
  const minConf = typeof params === 'string' ? minConfArg : params.minConfidence;
  const since = typeof params === 'string' ? readDateInput('sinceInput') : (params.since || null);
  const until = typeof params === 'string' ? readDateInput('untilInput') : (params.until || null);
  const interval = typeof params === 'string'
    ? currentTimelineInterval()
    : (params.timelineInterval || 'month');
  const showTimeline = typeof params === 'string'
    ? timelineEnabled()
    : (params.showTimeline ?? true);

  lastGraphQuery = {
    seedName,
    seedId,
    depth,
    minConf,
    since,
    until,
    interval,
    showTimeline,
  };

  const btn = document.getElementById('vizBtn');
  btn.disabled = true;
  btn.textContent = 'Loading...';
  try {
    const payload = {
      depth,
      min_confidence: minConf,
      since,
      until,
    };
    if (seedId) {
      payload.seed_id = seedId;
    } else {
      payload.seed_name = seedName;
    }
    const res = await apiFetch('/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const e = await res.json();
      throw new Error(e.detail || 'Query failed');
    }
    const data = await res.json();
    renderGraph(data);
    if (showTimeline) {
      try {
        await loadTimeline(seedName, {
          seedId,
          depth,
          minConf,
          since,
          until,
          interval,
        });
      } catch (timelineErr) {
        hideTimelinePanel();
        toast(`Timeline unavailable: ${timelineErr.message}`, 'error');
      }
    } else {
      hideTimelinePanel();
    }
    toast(`Loaded ${data.nodes.length} nodes, ${data.edges.length} edges`, 'success');
  } catch (e) {
    toast(e.message, 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Visualize';
  }
}

async function loadTimeline(seedName, { seedId, depth, minConf, since, until, interval }) {
  const query = new URLSearchParams({
    depth: String(depth),
    min_confidence: String(minConf),
    interval,
  });
  if (seedId) {
    query.set('entity_id', seedId);
  } else {
    query.set('entity_name', seedName);
  }
  if (since) query.set('since', since);
  if (until) query.set('until', until);

  const res = await apiFetch('/api/timeline/entity?' + query.toString());
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || 'Timeline query failed');
  }
  const data = await res.json();
  renderTimeline(data);
}

function renderTimeline(data) {
  timelineData = data;
  const panel = document.getElementById('timelinePanel');
  const title = document.getElementById('timelineTitle');
  const meta = document.getElementById('timelineMeta');
  const svgEl = document.getElementById('timelineSvg');
  const empty = document.getElementById('timelineEmpty');
  if (!panel || !title || !meta || !svgEl || !empty) return;

  panel.style.display = 'block';
  title.textContent = `Temporal activity: ${data.entity?.name || 'entity'}`;
  meta.textContent = `${data.interval} buckets · depth ${data.depth} · ${data.bucket_count} points`;

  const buckets = Array.isArray(data.buckets) ? data.buckets : [];
  d3.select(svgEl).selectAll('*').remove();

  if (!buckets.length) {
    svgEl.style.display = 'none';
    empty.style.display = 'block';
    return;
  }

  svgEl.style.display = 'block';
  empty.style.display = 'none';

  const W = Math.max(svgEl.clientWidth, 200);
  const H = Math.max(svgEl.clientHeight, 80);
  const margin = { top: 8, right: 12, bottom: 22, left: 34 };
  const innerW = Math.max(W - margin.left - margin.right, 10);
  const innerH = Math.max(H - margin.top - margin.bottom, 10);

  const parsed = buckets
    .map(b => ({
      t: new Date(b.bucket_start),
      relationCount: Number(b.relation_count || 0),
      evidenceCount: Number(b.evidence_count || 0),
      incomingCount: Number(b.incoming_relation_count || 0),
      outgoingCount: Number(b.outgoing_relation_count || 0),
    }))
    .filter(d => !Number.isNaN(d.t.getTime()))
    .sort((a, b) => a.t - b.t);

  if (!parsed.length) {
    svgEl.style.display = 'none';
    empty.style.display = 'block';
    return;
  }

  const minT = parsed[0].t;
  const maxT = parsed[parsed.length - 1].t;
  const minTime = minT.getTime();
  const maxTime = maxT.getTime();
  const adjustedMax = maxTime === minTime ? minTime + 24 * 60 * 60 * 1000 : maxTime;

  const x = d3.scaleTime()
    .domain([new Date(minTime), new Date(adjustedMax)])
    .range([0, innerW]);

  const maxY = d3.max(parsed, d => Math.max(d.relationCount, d.evidenceCount)) || 1;
  const y = d3.scaleLinear()
    .domain([0, maxY])
    .nice()
    .range([innerH, 0]);

  const root = d3.select(svgEl)
    .attr('viewBox', `0 0 ${W} ${H}`)
    .attr('preserveAspectRatio', 'none');
  const chart = root.append('g')
    .attr('transform', `translate(${margin.left},${margin.top})`);

  const barWidth = Math.max(2, Math.min(14, innerW / parsed.length / 2));
  chart.selectAll('.timeline-bar')
    .data(parsed)
    .enter()
    .append('rect')
    .attr('class', 'timeline-bar')
    .attr('x', d => x(d.t) - barWidth / 2)
    .attr('y', d => y(d.evidenceCount))
    .attr('width', barWidth)
    .attr('height', d => innerH - y(d.evidenceCount));

  const line = d3.line()
    .x(d => x(d.t))
    .y(d => y(d.relationCount));
  chart.append('path')
    .datum(parsed)
    .attr('class', 'timeline-line')
    .attr('d', line);

  chart.selectAll('.timeline-dot')
    .data(parsed)
    .enter()
    .append('circle')
    .attr('class', 'timeline-dot')
    .attr('cx', d => x(d.t))
    .attr('cy', d => y(d.relationCount))
    .attr('r', 2.8)
    .append('title')
    .text(d => {
      const date = d.t.toISOString().slice(0, 10);
      return `${date}
relations=${d.relationCount}
evidence=${d.evidenceCount}
incoming=${d.incomingCount}
outgoing=${d.outgoingCount}`;
    });

  chart.append('g')
    .attr('class', 'timeline-axis')
    .attr('transform', `translate(0,${innerH})`)
    .call(d3.axisBottom(x).ticks(6));

  chart.append('g')
    .attr('class', 'timeline-axis')
    .call(d3.axisLeft(y).ticks(4));
}

function hideTimelinePanel() {
  timelineData = null;
  const panel = document.getElementById('timelinePanel');
  const svgEl = document.getElementById('timelineSvg');
  const empty = document.getElementById('timelineEmpty');
  if (panel) panel.style.display = 'none';
  if (svgEl) d3.select(svgEl).selectAll('*').remove();
  if (empty) empty.style.display = 'none';
}

/* ── selection helpers ──────────────────── */
function clearSelection() {
  selected.nodes.clear();
  selected.edges.clear();
  updateSelectionVisuals();
}

function toggleSelectNode(id) {
  if (selected.nodes.has(id)) selected.nodes.delete(id);
  else selected.nodes.add(id);
  updateSelectionVisuals();
}

function toggleSelectEdge(id) {
  if (selected.edges.has(id)) selected.edges.delete(id);
  else selected.edges.add(id);
  updateSelectionVisuals();
}

function updateSelectionVisuals() {
  if (!g) return;
  g.selectAll('.node').classed('selected', d => selected.nodes.has(d.id));
  g.selectAll('.link').classed('selected', d => selected.edges.has(d.id));
  const total = selected.nodes.size + selected.edges.size;
  const btn = document.getElementById('deleteSelectedBtn');
  const cnt = document.getElementById('selCount');
  if (btn) btn.style.display = total > 0 ? 'inline-flex' : 'none';
  if (cnt) cnt.textContent = total;
}

/* ── lasso rectangle drag ──────────────── */
const lassoDrag = d3.drag()
  .on('start', function(event) {
    if (!selectMode) return;
    const [x, y] = d3.pointer(event, g.node());
    g.append('rect')
      .attr('class', 'lasso-rect')
      .attr('x', x).attr('y', y)
      .attr('width', 0).attr('height', 0)
      .datum({ x0: x, y0: y });
  })
  .on('drag', function(event) {
    const rect = g.select('.lasso-rect');
    if (rect.empty()) return;
    const d = rect.datum();
    const [cx, cy] = d3.pointer(event, g.node());
    rect.attr('x', Math.min(d.x0, cx))
        .attr('y', Math.min(d.y0, cy))
        .attr('width', Math.abs(cx - d.x0))
        .attr('height', Math.abs(cy - d.y0));
  })
  .on('end', function(event) {
    const rect = g.select('.lasso-rect');
    if (rect.empty()) return;
    const rx = +rect.attr('x'), ry = +rect.attr('y');
    const rw = +rect.attr('width'), rh = +rect.attr('height');
    rect.remove();
    if (rw < 5 && rh < 5) return; // too small, ignore
    // select nodes inside the rectangle
    if (graphData) {
      graphData.nodes.forEach(n => {
        if (n.x >= rx && n.x <= rx + rw && n.y >= ry && n.y <= ry + rh) {
          selected.nodes.add(n.id);
        }
      });
    }
    // select edges whose midpoint is inside the rectangle
    if (g) {
      g.selectAll('.link').each(d => {
        const mx = (d.source.x + d.target.x) / 2;
        const my = (d.source.y + d.target.y) / 2;
        if (mx >= rx && mx <= rx + rw && my >= ry && my <= ry + rh) {
          selected.edges.add(d.id);
        }
      });
    }
    updateSelectionVisuals();
  });

/* ── clear ─────────────────────────────── */
function clearGraph() {
  document.querySelectorAll('#graphArea svg.kg-svg').forEach(el => el.remove());
  document.getElementById('graphEmpty').style.display = 'flex';
  document.getElementById('graphToolbar').style.display = 'none';
  const er = document.getElementById('exportRow');
  if (er) er.style.display = 'none';
  if (sim) sim.stop();
  sim = null;
  graphData = null;
  selectMode = false;
  clearSelection();
  const smb = document.getElementById('selectModeBtn');
  if (smb) smb.classList.remove('active');
  hideTimelinePanel();
}

/* ── render ────────────────────────────── */
function renderGraph(data) {
  clearGraph();
  if (!data.nodes.length) { toast('No data to display', 'error'); return; }
  graphData = data;

  document.getElementById('graphEmpty').style.display = 'none';
  document.getElementById('graphToolbar').style.display = 'flex';
  const exportRow = document.getElementById('exportRow');
  if (exportRow) exportRow.style.display = 'flex';

  const area = document.getElementById('graphArea');
  const W = area.clientWidth;
  const H = area.clientHeight;

  zoomBehavior = d3.zoom().scaleExtent([0.1, 8]).on('zoom', e => g.attr('transform', e.transform));

  svg = d3.select('#graphArea')
    .append('svg')
    .attr('class', 'kg-svg')
    .attr('width', W)
    .attr('height', H)
    .call(zoomBehavior);

  svg.on('click', () => hideCtxMenu());

  g = svg.append('g');

  // build links array for d3.forceLink
  const links = data.edges.map(e => ({
    id: e.id,
    source: e.subject_id,
    target: e.object_id,
    predicate: e.predicate,
    confidence: e.confidence,
    origin: e.attrs?.origin || 'extracted',
  }));

  const link = g.selectAll('.link')
    .data(links)
    .enter().append('line')
    .attr('class', d => {
      if (d.origin === 'inferred') return 'link inferred';
      if (d.origin === 'cooccurrence') return 'link cooccurrence';
      return 'link';
    })
    .attr('stroke-width', d => 1 + d.confidence)
    .style('cursor', 'pointer')
    .on('click', (event, d) => {
      if (selectMode) { event.stopPropagation(); toggleSelectEdge(d.id); }
    })
    .on('dblclick', (event, d) => {
      if (selectMode) return;
      event.stopPropagation();
      explainRelation(d.id, d.predicate);
    });

  const edgeLabel = g.selectAll('.edge-label')
    .data(links)
    .enter().append('text')
    .attr('class', 'edge-label')
    .text(d => d.predicate);

  const node = g.selectAll('.node')
    .data(data.nodes)
    .enter().append('g')
    .attr('class', 'node')
    .call(d3.drag()
      .on('start', dragstarted)
      .on('drag', dragged)
      .on('end', dragended));

  node.append('circle')
    .attr('r', d => {
      const deg = links.filter(l =>
        l.source === d.id || l.target === d.id ||
        l.source.id === d.id || l.target.id === d.id
      ).length;
      return 10 + Math.min(deg * 2, 12);
    })
    .attr('fill', d => nodeColor(d))
    .attr('stroke', '#1e293b')
    .attr('stroke-width', 1.5)
    .style('cursor', 'pointer')
    .on('mouseover', function() { d3.select(this).attr('stroke-width', 2.5); })
    .on('mouseout', function(event, d) {
      d3.select(this).attr('stroke-width', selected.nodes.has(d.id) ? 3 : 1.5);
    })
    .on('click', (event, d) => {
      if (selectMode) { event.stopPropagation(); toggleSelectNode(d.id); }
    })
    .on('contextmenu', (event, d) => { event.preventDefault(); showCtxMenu(event, d); })
    .on('dblclick', (event, d) => { event.stopPropagation(); expandNode(d); });

  node.append('text')
    .attr('class', 'node-label')
    .attr('x', 18)
    .attr('y', 4)
    .text(d => d.name);

  sim = d3.forceSimulation(data.nodes)
    .force('link', d3.forceLink(links).id(d => d.id).distance(160))
    .force('charge', d3.forceManyBody().strength(-400))
    .force('center', d3.forceCenter(W / 2, H / 2))
    .force('collision', d3.forceCollide(30));

  sim.on('tick', () => {
    link
      .attr('x1', d => d.source.x)
      .attr('y1', d => d.source.y)
      .attr('x2', d => d.target.x)
      .attr('y2', d => d.target.y);

    node.attr('transform', d => `translate(${d.x},${d.y})`);

    edgeLabel
      .attr('x', d => (d.source.x + d.target.x) / 2)
      .attr('y', d => (d.source.y + d.target.y) / 2);
  });

  // Re-apply select mode if it was active before re-render
  if (selectMode) {
    svg.on('.zoom', null);
    svg.call(lassoDrag);
    svg.style('cursor', 'crosshair');
  }
}

/* ── drag handlers ─────────────────────── */
function dragstarted(event) {
  if (!event.active) sim.alphaTarget(0.3).restart();
  event.subject.fx = event.subject.x;
  event.subject.fy = event.subject.y;
}
function dragged(event) {
  event.subject.fx = event.x;
  event.subject.fy = event.y;
}
function dragended(event) {
  if (!event.active) sim.alphaTarget(0);
  // nodes stay pinned after drag
}

/* ── context menu ──────────────────────── */
function showCtxMenu(event, d) {
  ctxNode = d;
  const menu = document.getElementById('ctxMenu');
  const rect = document.getElementById('graphArea').getBoundingClientRect();
  menu.style.left = (event.clientX - rect.left) + 'px';
  menu.style.top = (event.clientY - rect.top) + 'px';
  menu.classList.add('show');
  document.getElementById('ctxPin').textContent = d.fx != null ? 'Unpin node' : 'Pin node';
}

function hideCtxMenu() {
  document.getElementById('ctxMenu').classList.remove('show');
  ctxNode = null;
}

/* ── node operations ───────────────────── */
function togglePin(d) {
  if (d.fx != null) { d.fx = null; d.fy = null; }
  else { d.fx = d.x; d.fy = d.y; }
  sim.alpha(0.1).restart();
}

function removeNode(nodeId) {
  graphData.nodes = graphData.nodes.filter(n => n.id !== nodeId);
  graphData.edges = graphData.edges.filter(e => e.subject_id !== nodeId && e.object_id !== nodeId);
  renderGraph(graphData);
  toast('Node removed', 'success');
}

async function explainRelation(relationId, fallbackPredicate) {
  try {
    const res = await apiFetch('/explain?relation_id=' + encodeURIComponent(relationId));
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Relation explain failed');
    }
    const data = await res.json();
    const predicate = data.relation?.predicate || fallbackPredicate || 'relation';
    const provenanceCount = Array.isArray(data.provenance) ? data.provenance.length : 0;
    const runCount = Array.isArray(data.runs) ? data.runs.length : 0;
    toast(`${predicate}: ${provenanceCount} provenance item(s), ${runCount} run(s)`, 'success');
  } catch (e) {
    toast(e.message || 'Could not load relation provenance', 'error');
  }
}

async function expandNode(d) {
  try {
    const temporal = currentTemporalFilters();
    if (lastGraphQuery) {
      lastGraphQuery.since = temporal.since;
      lastGraphQuery.until = temporal.until;
      lastGraphQuery.interval = currentTimelineInterval();
    }
    const res = await apiFetch('/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        seed_id: d.id,
        depth: 1,
        min_confidence: getConf(),
        since: temporal.since,
        until: temporal.until,
      }),
    });
    if (!res.ok) throw new Error('Expand failed');
    const data = await res.json();
    const existingIds = new Set(graphData.nodes.map(n => n.id));
    const existingEdges = new Set(graphData.edges.map(e => e.id));
    let added = 0;
    data.nodes.forEach(n => { if (!existingIds.has(n.id)) { graphData.nodes.push(n); added++; } });
    data.edges.forEach(e => { if (!existingEdges.has(e.id)) graphData.edges.push(e); });
    renderGraph(graphData);
    if (timelineEnabled() && lastGraphQuery) {
      try {
        await loadTimeline(lastGraphQuery.seedName, {
          seedId: lastGraphQuery.seedId,
          depth: lastGraphQuery.depth,
          minConf: lastGraphQuery.minConf,
          since: lastGraphQuery.since,
          until: lastGraphQuery.until,
          interval: lastGraphQuery.interval,
        });
      } catch (e) {
        toast(e.message, 'error');
      }
    }
    toast(`Expanded: +${added} nodes`, 'success');
  } catch (e) {
    toast(e.message, 'error');
  }
}

/* ── toolbar actions ───────────────────── */
function fitToView() {
  if (!graphData || !graphData.nodes.length) return;
  const area = document.getElementById('graphArea');
  const W = area.clientWidth, H = area.clientHeight;
  const xs = graphData.nodes.map(n => n.x || 0);
  const ys = graphData.nodes.map(n => n.y || 0);
  const x0 = Math.min(...xs) - 60, x1 = Math.max(...xs) + 60;
  const y0 = Math.min(...ys) - 60, y1 = Math.max(...ys) + 60;
  const scale = Math.min(W / (x1 - x0), H / (y1 - y0), 2);
  const tx = W / 2 - scale * (x0 + x1) / 2;
  const ty = H / 2 - scale * (y0 + y1) / 2;
  svg.transition().duration(500)
    .call(zoomBehavior.transform, d3.zoomIdentity.translate(tx, ty).scale(scale));
}

function togglePinAll() {
  if (!graphData) return;
  const anyPinned = graphData.nodes.some(n => n.fx != null);
  graphData.nodes.forEach(n => {
    if (anyPinned) { n.fx = null; n.fy = null; }
    else { n.fx = n.x; n.fy = n.y; }
  });
  sim.alpha(0.1).restart();
  toast(anyPinned ? 'All nodes unpinned' : 'All nodes pinned', 'success');
}
