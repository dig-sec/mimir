"""Combined (legacy) worker — runs LLM extraction in one process.

This module is kept for backward compatibility.  For production use,
prefer the dedicated workers:

* ``wellspring.worker.llm_worker``     — LLM extraction queue
* ``wellspring.worker.feedly_worker``  — Feedly connector sync
* ``wellspring.worker.opencti_worker`` — OpenCTI connector sync
* ``wellspring.worker.elastic_worker`` — Elasticsearch source sync

Running ``python -m wellspring.worker.main`` now launches only the LLM
extraction worker (the same as ``python -m wellspring.worker.llm_worker``).
"""

from __future__ import annotations

from .llm_worker import main

if __name__ == "__main__":
    main()
