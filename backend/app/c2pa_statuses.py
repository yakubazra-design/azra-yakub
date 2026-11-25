"""Shared C2PA and assessment status names.

Provenance validation and trust-policy selection both use these sets.
Neither module defines its own copy.
"""

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
