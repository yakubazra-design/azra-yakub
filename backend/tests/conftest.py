"""Isolated ledgers for the automated suite.

Every test that opens an application passes its own database under pytest's
temporary directory, which is outside ``data/``. This module does not connect
to ``data/ledger.sqlite`` and does not delete rows from it. Rate-limit rows
belong to the temporary database for that test, so visitor-address and
account limits start from an empty table without touching the live ledger.
"""

from pathlib import Path

import pytest

from app.ledger import enable_test_mode, refuse_test_ledger

enable_test_mode()


@pytest.fixture
def isolated_ledger(tmp_path: Path) -> Path:
    """A temporary database path that cannot resolve to the live ledger."""
    path = tmp_path / "ledger.sqlite"
    refuse_test_ledger(path)
    return path
