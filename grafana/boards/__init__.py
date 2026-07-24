"""One module per shipped dashboard.

A board module is DATA, not code: it declares which cataloged metrics get a
panel and in which section, plus its log panels. Titles, queries, aggregations,
units and layout are all derived from the catalog by ``boards.common.build``,
so a board module is never a second place a metric name, unit or label set can
drift from what the collector actually emits.

Adding a board: write the module, then add it to ``BOARDS`` in
``build_dashboard.py``. See AUTHORING.md.
"""
