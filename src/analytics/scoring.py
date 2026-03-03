"""
HallucinationScorer — Analytics module for hallucination metrics.

This module is owned by the Metrics & Risk Analysts (Role 5). It consumes
``AuditResult`` objects produced by ``GhostWireEngine`` and computes
aggregate statistics.

Usage:
    from src.analytics.scoring import HallucinationScorer
    from src.core.engine import AuditResult

    scorer = HallucinationScorer()
    rate = scorer.calculate_hallucination_rate(results)
    report = scorer.generate_report(results)
"""

from __future__ import annotations

import logging
from collections import Counter
from typing import Dict, List, Any

# We import the type only — no runtime dependency on the engine internals.
from src.core.engine import AuditResult

logger = logging.getLogger(__name__)


class HallucinationScorer:
    """
    Computes hallucination metrics from a batch of ``AuditResult`` objects.
    """

    @staticmethod
    def calculate_hallucination_rate(results: List[AuditResult]) -> float:
        """
        Return the hallucination rate as a float in [0.0, 1.0].

        Parameters
        ----------
        results : list[AuditResult]
            Audit results from ``GhostWireEngine.run_audit``.

        Returns
        -------
        float
            Fraction of results flagged as hallucinations.
        """
        if not results:
            return 0.0
        hallucinated = sum(1 for r in results if r.is_hallucination)
        rate = hallucinated / len(results)
        logger.info("Hallucination rate: %.2f%% (%d/%d)", rate * 100, hallucinated, len(results))
        return rate

    @staticmethod
    def calculate_risk_distribution(results: List[AuditResult]) -> Dict[int, int]:
        """
        Group audit results by ``risk_level`` (1‑5).

        Returns
        -------
        dict[int, int]
            Mapping of risk_level → count.
        """
        distribution: Dict[int, int] = Counter(r.risk_level for r in results)
        # Ensure all levels are represented.
        for level in range(1, 6):
            distribution.setdefault(level, 0)
        return dict(sorted(distribution.items()))

    @staticmethod
    def calculate_average_confidence(results: List[AuditResult]) -> float:
        """
        Return the mean confidence score across all audit results.
        """
        if not results:
            return 0.0
        return sum(r.confidence for r in results) / len(results)
    @staticmethod
    def calculate_accuracy(results: List[AuditResult]) -> float:
        """
        Accuracy = 1 - hallucination rate.
        Returns value in [0.0, 1.0]
        """
        if not results:
            return 0.0
        hallucination_rate = HallucinationScorer.calculate_hallucination_rate(results)
        return 1.0 - hallucination_rate
    @staticmethod
    def calculate_calibration_gap(results: List[AuditResult]) -> float:
        """
        Measures difference between average confidence and actual accuracy.
        Higher gap = more dangerous hallucination behavior.
        """
        if not results:
            return 0.0

        avg_conf = HallucinationScorer.calculate_average_confidence(results)
        accuracy = HallucinationScorer.calculate_accuracy(results)

        return abs(avg_conf - accuracy)
    @staticmethod
    def calculate_reliability_score(results: List[AuditResult]) -> float:
        """
        Weighted Ghostwire Reliability Formula:

        Reliability =
            (0.5 × Accuracy)
          + (0.3 × (1 - Calibration Gap))
          + (0.2 × (1 - Hallucination Rate))

        Returns value in [0.0, 1.0]
        """
        if not results:
            return 0.0

        accuracy = HallucinationScorer.calculate_accuracy(results)
        halluc_rate = HallucinationScorer.calculate_hallucination_rate(results)
        calibration_gap = HallucinationScorer.calculate_calibration_gap(results)

        reliability = (
            (0.5 * accuracy)
            + (0.3 * (1 - calibration_gap))
            + (0.2 * (1 - halluc_rate))
        )

        return max(0.0, min(1.0, reliability))
    @staticmethod
    def assign_risk_grade(reliability_score: float) -> str:
        """
        Convert reliability score to grade.
        """
        if reliability_score >= 0.85:
            return "A"
        elif reliability_score >= 0.70:
            return "B"
        elif reliability_score >= 0.50:
            return "C"
        elif reliability_score >= 0.30:
            return "D"
        else:
            return "F"
@staticmethod
def generate_report(results: List[AuditResult]) -> Dict[str, Any]:
    """
    Produce an extended Ghostwire reliability report suitable for JSON serialization.

    Returns
    -------
    dict
        {
            "total_audits": int,
            "hallucination_count": int,
            "hallucination_rate": float,
            "accuracy": float,
            "average_confidence": float,
            "calibration_gap": float,
            "reliability_score": float,
            "risk_grade": str,
            "risk_distribution": dict,
            "high_risk_items": list[dict],
        }
    """

    scorer = HallucinationScorer

    if not results:
        return {
            "total_audits": 0,
            "hallucination_count": 0,
            "hallucination_rate": 0.0,
            "accuracy": 0.0,
            "average_confidence": 0.0,
            "calibration_gap": 0.0,
            "reliability_score": 0.0,
            "risk_grade": "N/A",
            "risk_distribution": {},
            "high_risk_items": [],
        }

    hallucination_count = sum(1 for r in results if r.is_hallucination)

    hallucination_rate = scorer.calculate_hallucination_rate(results)
    accuracy = scorer.calculate_accuracy(results)
    average_confidence = scorer.calculate_average_confidence(results)
    calibration_gap = scorer.calculate_calibration_gap(results)
    reliability_score = scorer.calculate_reliability_score(results)
    risk_grade = scorer.assign_risk_grade(reliability_score)

    report: Dict[str, Any] = {
        "total_audits": len(results),
        "hallucination_count": hallucination_count,
        "hallucination_rate": hallucination_rate,
        "accuracy": accuracy,
        "average_confidence": average_confidence,
        "calibration_gap": calibration_gap,
        "reliability_score": reliability_score,
        "risk_grade": risk_grade,
        "risk_distribution": scorer.calculate_risk_distribution(results),
        "high_risk_items": [
            r.to_dict() for r in results
            if r.is_hallucination and r.risk_level >= 4
        ],
    }

    logger.info(
        "Report generated — %d audits | Reliability: %.2f | Grade: %s",
        len(results),
        reliability_score,
        risk_grade,
    )

    return report
