"""Combined (legacy) worker — runs LLM extraction in one process.

This module is kept for backward compatibility.  For production use,
prefer the dedicated workers:

* ``mimir.worker.llm_worker``      — LLM extraction queue
* ``mimir.worker.feedly_worker``   — Feedly connector sync
* ``mimir.worker.opencti_worker``  — OpenCTI connector sync
* ``mimir.worker.elastic_worker``  — Elasticsearch source sync
* ``mimir.worker.malware_worker``  — Malware feed sync (MWDB / dailymalwarefeed)

Running ``python -m mimir.worker.main`` now launches only the LLM
extraction worker (the same as ``python -m mimir.worker.llm_worker``).
"""

from __future__ import annotations

from .llm_worker import main

if __name__ == "__main__":
    main()
