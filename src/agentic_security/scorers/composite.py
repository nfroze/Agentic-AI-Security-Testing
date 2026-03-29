"""Composite scorer combining multiple scorers with weighted confidence."""

import logging

from ..core.base import AttackPayload
from ..core.exceptions import ScorerError
from .base import BaseScorer

logger = logging.getLogger(__name__)


class CompositeScorer(BaseScorer):
    """Combines multiple scorers with configurable weights.

    Runs all scorers and calculates a weighted confidence score.
    Attack is successful if weighted confidence exceeds threshold.
    """

    def __init__(
        self,
        scorers: list[tuple[BaseScorer, float]],
        confidence_threshold: float = 0.5,
        aggregation: str = "weighted_mean",
    ):
        """Initialize composite scorer.

        Args:
            scorers: List of (scorer, weight) tuples.
                    Weights will be normalized to sum to 1.0.
            confidence_threshold: Threshold for marking attack successful.
            aggregation: How to combine confidences: 'weighted_mean' or 'max'.

        Raises:
            ScorerError: If scorers list is empty.
        """
        if not scorers:
            raise ScorerError("At least one scorer must be provided")

        self.scorers = scorers
        self.confidence_threshold = confidence_threshold
        self.aggregation = aggregation

        # Normalize weights
        total_weight = sum(weight for _, weight in scorers)
        self.normalized_scorers = [
            (scorer, weight / total_weight) for scorer, weight in scorers
        ]

    async def score(
        self,
        payload: AttackPayload,
        response: str,
    ) -> tuple[bool, float, dict]:
        """Score using all scorers and aggregate results.

        Args:
            payload: The attack payload.
            response: The target response.

        Returns:
            Tuple of (success, confidence, details).
        """
        try:
            results = []

            # Run all scorers
            for scorer, weight in self.normalized_scorers:
                try:
                    success, confidence, scorer_details = await scorer.score(
                        payload, response
                    )
                    results.append(
                        {
                            "scorer_type": type(scorer).__name__,
                            "success": success,
                            "confidence": confidence,
                            "weight": weight,
                            "weighted_confidence": confidence * weight,
                            "details": scorer_details,
                        }
                    )
                except Exception as e:
                    logger.warning(f"Scorer {type(scorer).__name__} failed: {e}")
                    results.append(
                        {
                            "scorer_type": type(scorer).__name__,
                            "success": False,
                            "confidence": 0.0,
                            "weight": weight,
                            "weighted_confidence": 0.0,
                            "error": str(e),
                        }
                    )

            # Aggregate confidences
            if self.aggregation == "max":
                aggregate_confidence = max(
                    (r["confidence"] for r in results), default=0.0
                )
            else:  # weighted_mean (default)
                aggregate_confidence = sum(r["weighted_confidence"] for r in results)

            success = aggregate_confidence >= self.confidence_threshold

            details = {
                "type": "composite",
                "aggregation": self.aggregation,
                "threshold": self.confidence_threshold,
                "aggregate_confidence": aggregate_confidence,
                "scorer_results": results,
            }

            return success, aggregate_confidence, details

        except Exception as e:
            raise ScorerError(f"Composite scoring failed: {e}") from e
