from __future__ import annotations

import json


def _normalize_root_path(root_path: str) -> str:
    value = str(root_path or "").strip()
    if not value or value == "/":
        return ""
    if not value.startswith("/"):
        value = "/" + value
    return value.rstrip("/")


def render_root_ui(root_path: str = "", api_base_url: str = "") -> str:
    """Render the shell HTML — all logic lives in static JS/CSS files."""
    root_prefix = _normalize_root_path(root_path)
    static_prefix = f"{root_prefix}/static" if root_prefix else "/static"
    docs_href = f"{root_prefix}/docs" if root_prefix else "/docs"
    root_path_json = json.dumps(root_prefix)
    api_base_json = json.dumps(str(api_base_url or "").strip())
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Mimir</title>
  <link rel="stylesheet" href="{static_prefix}/style.css" />
</head>
<body>

  <!-- ─── HEADER ──────────────────────────── -->
  <header>
    <h1>Mimir</h1>
    <div class="tab-bar">
      <button class="tab-btn active" data-tab="explore">Explore</button>
      <button class="tab-btn" data-tab="pir">PIR</button>
    </div>
    <div class="spacer"></div>
    <span id="statsBar" style="font-size:12px;color:#6b7280;font-family:monospace"></span>
    <a href="{docs_href}" target="_blank" class="btn btn-outline btn-sm">API Docs</a>
  </header>

  <!-- ─── INGESTION PROGRESS ──────────────── -->
  <div class="ingest-bar" id="ingestBar">
    <div class="ingest-bar-inner">
      <div class="ingest-counts" id="ingestCounts"></div>
      <div class="ingest-track">
        <div class="ingest-fill" id="ingestFill"></div>
      </div>
      <div class="ingest-rate" id="ingestRate"></div>
    </div>
  </div>

  <!-- ─── MAIN ────────────────────────────── -->
  <main>
    <aside class="sidebar">

      <!-- == EXPLORE PANEL == -->
      <div class="panel active" id="panelExplore">
        <div class="sidebar-section">
          <div class="search-wrap">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/>
            </svg>
            <input type="text" id="searchInput" placeholder="Search entities..." autocomplete="off" />
          </div>
          <div class="controls">
            <div class="ctrl-group">
              <label>Entity type</label>
              <select id="entityTypeInput">
                <option value="">All types</option>
                <option value="threat_actor">Threat Actor</option>
                <option value="malware">Malware</option>
                <option value="vulnerability">Vulnerability</option>
                <option value="attack_pattern">Attack Pattern</option>
                <option value="campaign">Campaign</option>
                <option value="tool">Tool</option>
                <option value="indicator">Indicator</option>
                <option value="infrastructure">Infrastructure</option>
                <option value="identity">Identity</option>
                <option value="mitigation">Mitigation</option>
                <option value="report">Report</option>
              </select>
            </div>
            <div class="ctrl-group">
              <label>Entity ID (optional)</label>
              <input type="text" id="entityIdInput" placeholder="Exact entity ID" />
            </div>
          </div>
          <div class="controls">
            <div class="ctrl-group">
              <label class="label-help">
                <span>Depth</span>
                <button
                  type="button"
                  class="help-dot"
                  aria-label="Depth help"
                  data-tip="Depth controls graph expansion hops from the seed entity. 0 = seed only, 1 = direct neighbors, 2+ expands further and can grow results quickly."
                >?</button>
              </label>
              <input type="number" id="depthInput" value="2" min="0" max="5" />
            </div>
            <div class="ctrl-group">
              <label>Min confidence</label>
              <input type="range" id="confInput" value="0.0" min="0" max="1" step="0.05" />
              <span class="range-val" id="confVal">0.0</span>
            </div>
          </div>
          <div class="controls temporal-controls">
            <div class="ctrl-group">
              <label>Since</label>
              <input type="datetime-local" id="sinceInput" />
            </div>
            <div class="ctrl-group">
              <label>Until</label>
              <input type="datetime-local" id="untilInput" />
            </div>
          </div>
          <div class="controls temporal-controls">
            <div class="ctrl-group">
              <label>Timeline interval</label>
              <select id="timelineInterval">
                <option value="day">Day</option>
                <option value="week">Week</option>
                <option value="month" selected>Month</option>
                <option value="quarter">Quarter</option>
                <option value="year">Year</option>
              </select>
            </div>
            <div class="ctrl-group checkbox-group">
              <label>&nbsp;</label>
              <label class="check-inline">
                <input type="checkbox" id="timelineToggle" checked />
                <span>Show timeline</span>
              </label>
            </div>
          </div>
          <!-- type filter toggles -->
          <div class="type-toggles" id="typeToggles">
            <div class="type-toggles-header">
              <span class="type-toggles-title">Include Types</span>
              <button class="type-toggles-all" id="toggleAllTypesBtn" title="Toggle all on/off">All</button>
            </div>
            <div class="type-toggle-list" id="typeToggleList"></div>
          </div>
          <div class="btn-row">
            <button class="btn btn-primary" id="vizBtn" style="flex:1">Visualize</button>
          </div>
          <div class="btn-row" id="exportRow" style="display:none;margin-top:6px">
            <div class="export-dropdown sidebar-export" id="exportDropdown" style="flex:1">
              <button class="btn btn-outline" id="exportBtn" style="width:100%;font-size:12px">&#x2B07; Export visible graph</button>
              <div class="export-menu" id="exportMenu">
                <button class="export-item" data-format="stix">STIX 2.1 (.json)</button>
                <button class="export-item" data-format="json">JSON (.json)</button>
                <button class="export-item" data-format="csv">CSV (.zip)</button>
                <button class="export-item" data-format="graphml">GraphML &mdash; Gephi (.graphml)</button>
                <button class="export-item" data-format="markdown">Markdown (.md)</button>
              </div>
            </div>
          </div>
        </div>

        <!-- upload zone (inline) -->
        <div class="sidebar-section" style="padding-top:0">
          <div class="drop-zone" id="dropZone" style="padding:12px">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="margin:0 auto">
              <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/>
              <polyline points="17 8 12 3 7 8"/>
              <line x1="12" y1="3" x2="12" y2="15"/>
            </svg>
            <p style="margin:4px 0 0">Drop files here or click to browse</p>
            <span class="hint">.txt, .md, .csv, .json, .html, .pdf</span>
          </div>
          <input type="file" id="fileInput" multiple accept=".txt,.md,.csv,.json,.html,.log,.xml,.yaml,.yml,.py,.js,.ts,.pdf" hidden />
          <div class="file-list" id="fileList"></div>
          <div class="btn-row" id="uploadActions" style="display:none">
            <button class="btn btn-primary" id="uploadBtn" style="flex:1">Upload &amp; Process</button>
            <button class="btn btn-outline" id="clearFilesBtn">Clear</button>
          </div>
          <div class="btn-row" style="margin-top:8px">
            <button class="btn btn-primary" id="pullAllBtn" style="flex:1;font-size:12px">
              &#x1F504; Pull All Sources
            </button>
          </div>
          <div class="btn-row" style="margin-top:4px">
            <button class="btn btn-outline" id="feedlyPullBtn" style="flex:1;font-size:12px">
              &#x1F4E1; Feedly CTI
            </button>
            <button class="btn btn-outline" id="openctiPullBtn" style="flex:1;font-size:12px">
              &#x1F310; OpenCTI
            </button>
          </div>
          <div class="btn-row" style="margin-top:4px">
            <button class="btn btn-outline" id="scanFilesBtn" style="flex:1;font-size:12px">
              &#x1F4C1; Scan Folders
            </button>
            <button class="btn btn-outline" id="elasticPullBtn" style="flex:1;font-size:12px">
              &#x1F50D; ES Docs
            </button>
          </div>
        </div>

        <!-- entity list -->
        <div class="scroll-list" id="entityList">
          <div class="empty-state" style="padding:40px 0"><p>Type to search entities</p></div>
        </div>

        <!-- recent runs (collapsible) -->
        <div class="sidebar-section runs-section" id="runsList">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px">
            <label style="margin:0;font-weight:600;font-size:13px;cursor:pointer" id="runsToggle">&#9654; Recent runs</label>
            <div>
              <button class="btn btn-outline btn-sm" id="clearRunsBtn" title="Delete all runs" style="margin-right:4px">&times; Clear</button>
              <button class="btn btn-outline btn-sm" id="refreshRunsBtn">Refresh</button>
            </div>
          </div>
          <div id="runsContent" style="display:none">
            <div class="empty-state" style="padding:20px 0"><p>No runs yet</p></div>
          </div>
        </div>
      </div>
    </aside>

    <!-- == PIR DASHBOARD (full-width) == -->
    <div class="pir-dashboard" id="pirDashboard" style="display:none">
      <div class="pir-dash-header">
        <div class="pir-dash-title">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg>
          <h2>Priority Intelligence Requirements</h2>
        </div>
        <div class="pir-dash-controls">
          <div class="pir-toolbar-group">
            <label>From</label>
            <input type="date" id="pirDateFrom" />
          </div>
          <div class="pir-toolbar-group">
            <label>To</label>
            <input type="date" id="pirDateTo" />
          </div>
          <div class="pir-toolbar-group">
            <label>Show top</label>
            <select id="pirTopNInput">
              <option value="5" selected>5</option>
              <option value="10">10</option>
              <option value="20">20</option>
              <option value="50">50</option>
            </select>
          </div>
          <button class="btn btn-primary btn-sm" id="pirRefreshBtn">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15"/></svg>
            Refresh
          </button>
        </div>
      </div>
      <div class="pir-dash-body" id="pirList">
        <div class="pir-skeleton">
          <div class="pir-skeleton-card"></div>
          <div class="pir-skeleton-card"></div>
          <div class="pir-skeleton-card"></div>
          <div class="pir-skeleton-card"></div>
          <div class="pir-skeleton-card"></div>
        </div>
      </div>
    </div>

    <!-- == GRAPH AREA == -->
    <div class="graph-area" id="graphArea">
      <div class="graph-legend" id="graphLegend" style="display:none"></div>
      <div class="graph-toolbar" id="graphToolbar" style="display:none">
        <button class="btn btn-sm" id="zoomInBtn" title="Zoom in">+</button>
        <button class="btn btn-sm" id="zoomOutBtn" title="Zoom out">&minus;</button>
        <button class="btn btn-sm" id="fitBtn" title="Fit to view">&#8862;</button>
        <button class="btn btn-sm" id="pinBtn" title="Pin / unpin all">&#128204;</button>
        <span class="toolbar-sep"></span>
        <button class="btn btn-sm" id="selectModeBtn" title="Toggle select mode">&#9632; Select</button>
        <button class="btn btn-sm btn-danger" id="deleteSelectedBtn" title="Remove selected" style="display:none">&#x1F5D1; Remove (<span id="selCount">0</span>)</button>
        <button class="btn btn-sm" id="cleanEntityBtn" title="Remove nodes by entity">Clean</button>
        <button class="btn btn-sm" id="clearGraphBtn" title="Clear graph">&times;</button>
      </div>
      <div class="empty-state" id="graphEmpty">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
          <circle cx="6" cy="6" r="3"/><circle cx="18" cy="18" r="3"/>
          <circle cx="18" cy="6" r="3"/><path d="M8.5 8l7 7M8.5 6h7"/>
        </svg>
        <p>Search an entity and click Visualize</p>
      </div>
      <div class="timeline-panel" id="timelinePanel" style="display:none">
        <div class="timeline-head">
          <div class="timeline-title" id="timelineTitle">Temporal activity</div>
          <div class="timeline-meta" id="timelineMeta"></div>
        </div>
        <svg id="timelineSvg"></svg>
        <div class="timeline-empty" id="timelineEmpty" style="display:none">
          No temporal evidence in the selected window.
        </div>
      </div>
      <div class="context-menu" id="ctxMenu">
        <button class="ctx-item" id="ctxExpand">Expand this node</button>
        <button class="ctx-item" id="ctxPin">Pin / unpin</button>
        <button class="ctx-item" id="ctxExplain">Show provenance</button>
        <button class="ctx-item danger" id="ctxRemove">Remove node</button>
      </div>
    </div>
  </main>

  <!-- ─── TASK STATUS BAR ─────────────────── -->
  <div class="task-bar" id="taskBar" style="display:none">
    <span class="task-label">TASK:</span>
    <span class="task-badge running" id="taskBadge">running</span>
    <span class="task-progress" id="taskProgress"></span>
  </div>

  <div class="toasts" id="toasts"></div>

  <script>
    window.__MIMIR_ROOT_PATH__ = {root_path_json};
    window.__MIMIR_API_BASE__ = {api_base_json};
    // Backward compatibility for any older custom scripts.
    window.__WELLSPRING_ROOT_PATH__ = window.__MIMIR_ROOT_PATH__;
    window.__WELLSPRING_API_BASE__ = window.__MIMIR_API_BASE__;
  </script>
  <script src="{static_prefix}/vendor/d3.v7.min.js"></script>
  <script type="module" src="{static_prefix}/main.js"></script>
</body>
</html>"""
