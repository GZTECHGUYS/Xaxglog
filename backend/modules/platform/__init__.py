"""Xaxglog Phase 1-12 platform services.

The package keeps the upgrade work in one auditable layer instead of adding a
new Flask route group for every feature:

* ``store``        SQLite persistence for graph/timeline/provenance, workspaces,
                   module packs, plugins and settings.
* ``core``         Phase 1-3 intelligence core: graph, social coverage,
                   analytics and source health.
* ``ops``          Phase 4-7 runtime, module packs, offline cache, security.
* ``collab``       Phase 8 team workspaces, comments and assignments.
* ``ecosystem``    Phase 10-12 plugins, compliance/governance, observability.
* ``routes``       JSON API registered by ``routes/p9.py``.

Everything is optional at boot: a failure in this package is reported by
``CAPS["platform_ops"] = False`` and never takes the base dashboard down.
"""

__all__ = ["store", "core", "ops", "collab", "ecosystem", "routes"]
