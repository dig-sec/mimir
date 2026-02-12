import { initTabs, initSearch } from './sidebar.js';
import { initUpload, initRuns } from './ingest.js';
import { initGraph, loadGraph } from './graph.js';
import { initOpenCTI } from './opencti.js';
import { initPIR } from './pir.js';

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
