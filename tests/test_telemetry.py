import os
import json
import pytest
import numpy as np
from app.telemetry.drift_monitor import StatisticalDriftMonitor
from app.telemetry.audit_logger import ComplianceAuditLogger, AuditRecord

TEST_LOG = "test_audit_records.jsonl"

@pytest.fixture(autouse=True)
def cleanup_test_logs():
    if os.path.exists(TEST_LOG):
        os.remove(TEST_LOG)
    yield
    if os.path.exists(TEST_LOG):
        os.remove(TEST_LOG)

# ---------------------------------------------------------------------------
# Statistical Drift Monitor Tests (EU AI Act Article 15)
# ---------------------------------------------------------------------------

def test_drift_monitor_detects_distribution_stability():
    """Verify identical samples exhibit high p-values and zero drift."""
    monitor = StatisticalDriftMonitor(p_value_alpha=0.05)
    baseline_scores = [0.12, 0.15, 0.14, 0.13, 0.16, 0.11, 0.15, 0.14]
    monitor.register_baseline("latent_entropy", baseline_scores)

    current_window = [0.13, 0.14, 0.15, 0.12, 0.16, 0.14, 0.15, 0.13]
    report = monitor.evaluate_metric_drift("latent_entropy", current_window)

    assert report.drift_detected is False
    assert report.drift_severity == "NONE"
    assert report.ks_p_value > 0.05

def test_drift_monitor_flags_critical_distribution_shift():
    """Verify anomalous drift triggers rejection thresholds."""
    monitor = StatisticalDriftMonitor(p_value_alpha=0.05)
    # Calibrated baseline centered around ~0.15
    baseline_scores = [0.12, 0.14, 0.15, 0.13, 0.16, 0.15, 0.14, 0.12, 0.15, 0.13]
    monitor.register_baseline("ood_distance", baseline_scores)

    # Shifted production window centered around ~0.85
    shifted_window = [0.82, 0.89, 0.78, 0.91, 0.85, 0.88, 0.94, 0.79, 0.83, 0.87]
    report = monitor.evaluate_metric_drift("ood_distance", shifted_window)

    assert report.drift_detected is True
    assert report.drift_severity == "CRITICAL"
    assert report.ks_p_value < 0.01
    assert report.wasserstein_dist > 0.50

# ---------------------------------------------------------------------------
# Compliance Audit Logger Tests (EU AI Act Article 12)
# ---------------------------------------------------------------------------

def test_audit_logger_creates_tamper_evident_record():
    """Verify audit logger writes structured JSON and computes SHA-256 digest."""
    logger = ComplianceAuditLogger(log_path=TEST_LOG)

    record = logger.log_inference_event(
        tenant_id="tenant_uk",
        user_id="analyst_402",
        user_role="risk_examiner",
        raw_query="What is the capital reserve ratio?",
        sanitization_report={"delimiter_tampering": False, "decoded_payloads": []},
        ood_score=14.28,
        ood_rejected=False,
        canary_token="CONF_CANARY_A98F12",
        canary_leak_detected=False,
        requires_human_oversight=False,
        execution_trace=[{"step": "retrieve", "docs_found": 2}],
        final_output="Statutory ratio is 12.5%."
    )

    assert isinstance(record, AuditRecord)
    assert len(record.cryptographic_digest) == 64  # Valid SHA-256 hex string
    assert os.path.exists(TEST_LOG)

    # Read back from file and verify JSON schema
    with open(TEST_LOG, "r") as f:
        lines = f.readlines()
        assert len(lines) == 1
        data = json.loads(lines[0])
        assert data["tenant_id"] == "tenant_uk"
        assert data["cryptographic_digest"] == record.cryptographic_digest