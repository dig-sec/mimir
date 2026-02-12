from __future__ import annotations


def render_root_ui() -> str:
    """Render the shell HTML — all logic lives in static JS/CSS files."""
    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Wellspring</title>
  <link rel="stylesheet" href="/static/style.css" />
</head>
<body>

  <!-- ─── HEADER ──────────────────────────── -->
  <header>
    <h1>Wellspring</h1>
    <div class="tab-bar">
      <button class="tab-btn active" data-tab="explore">Explore</button>
    </div>
    <div class="spacer"></div>
    <span id="statsBar" style="font-size:12px;color:#6b7280;font-family:monospace"></span>
    <a href="/docs" target="_blank" class="btn btn-outline btn-sm">API Docs</a>
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
              <label>Depth</label>
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

    <!-- == GRAPH AREA == -->
    <div class="graph-area" id="graphArea">
      <div class="graph-toolbar" id="graphToolbar" style="display:none">
        <button class="btn btn-sm" id="zoomInBtn" title="Zoom in">+</button>
        <button class="btn btn-sm" id="zoomOutBtn" title="Zoom out">&minus;</button>
        <button class="btn btn-sm" id="fitBtn" title="Fit to view">&#8862;</button>
        <button class="btn btn-sm" id="pinBtn" title="Pin / unpin all">&#128204;</button>
        <span class="toolbar-sep"></span>
        <button class="btn btn-sm" id="selectModeBtn" title="Toggle select mode">&#9632; Select</button>
        <button class="btn btn-sm btn-danger" id="deleteSelectedBtn" title="Remove selected" style="display:none">&#x1F5D1; Remove (<span id="selCount">0</span>)</button>
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

  <script src="https://cdn.jsdelivr.net/npm/d3@7"></script>
  <script type="module" src="/static/main.js"></script>
</body>
</html>"""
