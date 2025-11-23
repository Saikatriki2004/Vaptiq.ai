# Backend/store.py
# Centralized in-memory store for MVP
# This prevents circular imports and ensures all modules share the same state.
scans_db = {}
mock_targets_db = {}
cve_cache = {
    "data": [],
    "last_updated": None
}
