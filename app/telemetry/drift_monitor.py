import numpy as np
from scipy.stats import ks_2samp, wasserstein_distance
from typing import List, Dict, Any, Tuple
from pydantic import BaseModel, Field

class DriftReport(BaseModel):
    metric_name: str
    ks_statistic: float
    ks_p_value: float
    wasserstein_dist: float
    drift_detected: bool = Field(
        ...,
        description="Flagged true if p-value < alpha (statistical shift detected)."
    )
    drift_severity: str = Field(
        ...,
        description="'NONE', 'MODERATE', or 'CRITICAL' based on distribution shift."
    )

class StatisticalDriftMonitor:
    """
    Evaluates distribution divergence between baseline calibration data
    and production inference windows (EU AI Act Article 15).
    """

    def __init__(self, p_value_alpha: float = 0.05, wasserstein_threshold: float = 0.35):
        self.alpha = p_value_alpha
        self.wasserstein_threshold = wasserstein_threshold
        self.baselines: Dict[str, np.ndarray] = {}

    def register_baseline(self, metric_name: str, values: List[float]):
        """Caches baseline distribution from validation or initial deployment window."""
        arr = np.array(values, dtype=np.float64)
        if len(arr) < 5:
            raise ValueError(f"Baseline requires at least 5 samples, got {len(arr)}.")
        self.baselines[metric_name] = arr

    def evaluate_metric_drift(self, metric_name: str, current_window: List[float]) -> DriftReport:
        """
        Runs two-sample KS-Test and Wasserstein Distance against registered baseline.
        """
        if metric_name not in self.baselines:
            raise KeyError(f"No registered baseline found for metric '{metric_name}'.")

        baseline = self.baselines[metric_name]
        current = np.array(current_window, dtype=np.float64)

        if len(current) < 5:
            raise ValueError(f"Current window requires at least 5 samples, got {len(current)}.")

        # 1. Two-sample Kolmogorov-Smirnov Test
        ks_res = ks_2samp(baseline, current)
        ks_stat = float(ks_res.statistic)
        p_val = float(ks_res.pvalue)

        # 2. Wasserstein (Earth Mover's) Distance
        w_dist = float(wasserstein_distance(baseline, current))

        # 3. Drift Evaluation Logic
        is_drifted = bool(p_val < self.alpha or w_dist > self.wasserstein_threshold)

        if not is_drifted:
            severity = "NONE"
        elif p_val < (self.alpha / 10.0) or w_dist > (self.wasserstein_threshold * 2.0):
            severity = "CRITICAL"
        else:
            severity = "MODERATE"

        return DriftReport(
            metric_name=metric_name,
            ks_statistic=round(ks_stat, 4),
            ks_p_value=round(p_val, 5),
            wasserstein_dist=round(w_dist, 4),
            drift_detected=is_drifted,
            drift_severity=severity
        )