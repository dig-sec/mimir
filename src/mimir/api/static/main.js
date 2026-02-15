import { initTabs, initSearch } from './sidebar.js';
import { initUpload, initRuns } from './ingest.js';
import { initGraph, loadGraph, renderGraph } from './graph.js';
import { initOpenCTI } from './opencti.js';
import { initPIR } from './pir.js';
import { initAsk } from './ask.js';
import { initStatus } from './status.js';
import { initPathFinder } from './pathfinder.js';

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
