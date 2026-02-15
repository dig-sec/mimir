import { initTabs, initSearch } from './sidebar.js';
import { initUpload, initRuns } from './ingest.js';
import { initGraph, loadGraph, renderGraph } from './graph.js';
import { initOpenCTI } from './opencti.js';
import { initPIR } from './pir.js';
import { initAsk } from './ask.js';
import { initStatus } from './status.js';
import { initPathFinder } from './pathfinder.js';
import { initMultiSearch } from './multisearch.js';

/* ── bootstrap ────────────────────────── */
initTabs();

const search = initSearch(params => {
  loadGraph(params);
});

initGraph(search.getConfidence);
initUpload();
initRuns();
initOpenCTI();
initPIR();
initAsk();
initStatus();
initPathFinder(renderGraph);
initMultiSearch(loadGraph, renderGraph);

/* ── toggle multi-search panel ─── */
const msToggle = document.getElementById('multiSearchToggle');
const msContent = document.getElementById('multiSearchContent');
if (msToggle && msContent) {
  msToggle.addEventListener('click', () => {
    const open = msContent.style.display !== 'none';
    msContent.style.display = open ? 'none' : '';
    msToggle.textContent = (open ? '\u25B6' : '\u25BC') + ' Parallel Searches';
  });
}
