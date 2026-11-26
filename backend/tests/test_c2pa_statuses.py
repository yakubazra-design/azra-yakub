"""Shared status constants and the provenance import boundary.

Import checks run in a fresh interpreter. The pytest process may already
have loaded the trust store through another test module.
"""

import os
import subprocess
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]

FAILURE_CODES = frozenset({
    "activation_inconsistent",
    "activation_record_corrupt",
    "activation_record_missing",
    "approval_substitution",
    "duplicate_approver",
    "no_committed_policy",
    "policy_downgrade",
    "policy_superseded",
    "root_pin_inconsistent",
    "root_pin_unavailable",
    "root_recovery_incomplete",
    "root_suspended",
    "root_suspension_unavailable",
    "sequence_conflict",
    "sequence_state_inconsistent",
    "sequence_state_stale",
    "suspension_history_unavailable",
    "suspension_regression",
    "suspension_state_stale",
    "trust_configuration",
    "unauthorized_approval",
    "untrusted_admin_key",
    "witness_conflict",
    "witness_corrupt",
    "witness_unavailable",
})
CREDENTIAL_STATUSES = frozenset({
    "no_credentials",
    "not_performed",
    "credentials_malformed",
    "credentials_invalid",
    "credentials_untrusted",
    "credentials_trusted",
})
ASSESSMENT_OUTCOMES = frozenset({
    "VERIFIED",
    "PARTIALLY_VERIFIED",
    "CONTRADICTED",
    "INSUFFICIENT_EVIDENCE",
    "POTENTIAL_MANIPULATION",
    "UNRESOLVED",
})


def _fresh(code: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(BACKEND)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return subprocess.run(
        [sys.executable, "-c", code],
        cwd=BACKEND.parent,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_importing_provenance_does_not_load_the_trust_store():
    completed = _fresh(
        "import sys\n"
        "import app.provenance\n"
        "assert 'app.trust_store' not in sys.modules\n"
        "assert 'app.c2pa_statuses' in sys.modules\n"
    )
    assert completed.returncode == 0, completed.stderr


def test_importing_the_ledger_does_not_load_the_trust_store():
    completed = _fresh(
        "import sys\n"
        "import app.ledger\n"
        "assert 'app.trust_store' not in sys.modules\n"
        "assert 'app.provenance' in sys.modules\n"
        "assert 'app.c2pa_statuses' in sys.modules\n"
    )
    assert completed.returncode == 0, completed.stderr


def test_provenance_and_trust_store_share_one_status_definition():
    from app.c2pa_statuses import (
        ASSESSMENT_OUTCOMES as shared_outcomes,
        CREDENTIAL_STATUSES as shared_credentials,
        FAILURE_CODES as shared_failures,
    )
    from app.provenance import (
        ASSESSMENT_OUTCOMES as provenance_outcomes,
        CREDENTIAL_STATUSES as provenance_credentials,
        FAILURE_CODES as provenance_failures,
    )
    from app.trust_store import (
        ASSESSMENT_OUTCOMES as trust_outcomes,
        CREDENTIAL_STATUSES as trust_credentials,
        FAILURE_CODES as trust_failures,
    )

    assert shared_failures is provenance_failures is trust_failures
    assert shared_credentials is provenance_credentials is trust_credentials
    assert shared_outcomes is provenance_outcomes is trust_outcomes
    assert shared_failures == FAILURE_CODES
    assert shared_credentials == CREDENTIAL_STATUSES
    assert shared_outcomes == ASSESSMENT_OUTCOMES
    assert shared_failures.isdisjoint(shared_credentials)
    assert shared_failures.isdisjoint(shared_outcomes)
    assert shared_credentials.isdisjoint(shared_outcomes)
