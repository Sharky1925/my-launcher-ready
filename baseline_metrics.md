# Baseline Metrics (2026-02-22)

## Regression + Security Test Baseline
Command:
- `PYTHONPATH=/Users/umutdemirkapu/mylauncher pytest -q /Users/umutdemirkapu/mylauncher/app/tests/test_security_and_cms.py`

Result:
- `43 passed`
- `0 failed`
- `18 warnings` (SQLAlchemy legacy `Query.get()` warnings only)

## Rough Endpoint Performance (local, in-memory SQLite, 5 samples each)
- `/`: avg 8.84 ms, max 33.35 ms
- `/services`: avg 3.34 ms, max 7.72 ms
- `/industries`: avg 3.31 ms, max 7.96 ms
- `/remote-support`: avg 3.15 ms, max 9.45 ms
- `/contact`: avg 2.34 ms, max 5.84 ms
- `/admin/login`: avg 1.56 ms, max 3.33 ms
- `/healthz`: avg 0.27 ms, max 0.45 ms
- `/readyz`: avg 0.43 ms, max 0.67 ms
- `/ticket-search`: avg 2.12 ms, max 3.95 ms

## Route Sync Baseline
Command path: `run_page_route_sync()` against fresh seeded app.

Before auto-register:
- `routes_scanned=16`
- `synced=0`
- `missing_page_document=16`
- `orphan_pages=1`

After auto-register:
- `routes_scanned=16`
- `missing_page_document=0`
- `unpublished_page_document=16` (expected until editorial publish)
- `auto_registered_pages=15`

Interpretation:
- Sync coverage and drift detection are now deterministic.
- Editorial publish workflow remains the gate from draft to live delivery.
