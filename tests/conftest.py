import pytest


@pytest.fixture(autouse=True)
def duckdb_analytics_mode(monkeypatch, request):
    if request.module.__name__.endswith("test_analytics_store"):
        return
    monkeypatch.setenv("FORENSIC_ANALYTICS_MODE", "duckdb")
