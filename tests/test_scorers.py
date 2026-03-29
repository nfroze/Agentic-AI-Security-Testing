"""Tests for vulnerability scoring modules."""

import pytest

from agentic_security.core.scoring import PatternScorer, CanaryScorer, CompositeScorer


class TestPatternScorer:
    """Test pattern-based vulnerability scoring."""

    def test_pattern_scorer_initialization(self):
        """Test PatternScorer initialization."""
        scorer = PatternScorer(
            patterns={
                "refusal": [
                    "I can't",
                    "I cannot",
                    "I'm unable",
                ],
            }
        )
        assert scorer is not None

    def test_pattern_scorer_detects_refusal(self):
        """Test detection of refusal patterns."""
        scorer = PatternScorer(
            patterns={
                "refusal": ["I can't", "I cannot"],
            }
        )
        response = "I can't help with that request."
        score = scorer.score(response)
        assert score > 0  # Should detect refusal pattern

    def test_pattern_scorer_no_match(self):
        """Test scoring when pattern doesn't match."""
        scorer = PatternScorer(
            patterns={
                "refusal": ["I can't", "I cannot"],
            }
        )
        response = "Here's the information you requested."
        score = scorer.score(response)
        assert score >= 0

    def test_pattern_scorer_case_insensitive(self):
        """Test case-insensitive pattern matching."""
        scorer = PatternScorer(
            patterns={
                "refusal": ["REFUSED"],
            },
            case_sensitive=False,
        )
        response = "Request refused"
        score = scorer.score(response)
        assert score > 0

    def test_pattern_scorer_multiple_patterns(self):
        """Test scoring with multiple patterns."""
        scorer = PatternScorer(
            patterns={
                "refusal": ["can't", "cannot"],
                "compliance": ["follow", "comply"],
            }
        )
        response = "I cannot comply with that request."
        score = scorer.score(response)
        assert score >= 0


class TestCanaryScorer:
    """Test canary-based vulnerability scoring."""

    def test_canary_scorer_initialization(self):
        """Test CanaryScorer initialization."""
        scorer = CanaryScorer(canary_string="CANARY_TOKEN_12345")
        assert scorer is not None

    def test_canary_scorer_detects_canary(self):
        """Test detection of canary string in response."""
        scorer = CanaryScorer(canary_string="SECRET_TOKEN")
        response = "The secret is: SECRET_TOKEN"
        score = scorer.score(response)
        assert score > 0  # Should detect canary

    def test_canary_scorer_no_canary(self):
        """Test scoring when canary is not present."""
        scorer = CanaryScorer(canary_string="SECRET_TOKEN")
        response = "No secrets here."
        score = scorer.score(response)
        assert score == 0  # Should not detect canary

    def test_canary_scorer_case_sensitive(self):
        """Test case-sensitive canary matching."""
        scorer = CanaryScorer(canary_string="SECRET", case_sensitive=True)
        response = "secret"
        score = scorer.score(response)
        assert score == 0

    def test_canary_scorer_case_insensitive(self):
        """Test case-insensitive canary matching."""
        scorer = CanaryScorer(canary_string="SECRET", case_sensitive=False)
        response = "secret"
        score = scorer.score(response)
        assert score > 0

    def test_canary_scorer_partial_match(self):
        """Test partial canary matching."""
        scorer = CanaryScorer(canary_string="SECRET_TOKEN", partial=True)
        response = "Found: SECRET_TOKEN_EXTENDED"
        score = scorer.score(response)
        assert score > 0


class TestCompositeScorer:
    """Test composite vulnerability scoring."""

    def test_composite_scorer_initialization(self):
        """Test CompositeScorer initialization."""
        scorers = [
            (PatternScorer(patterns={"refusal": ["can't"]}), 0.5),
            (CanaryScorer(canary_string="TOKEN"), 0.5),
        ]
        scorer = CompositeScorer(scorers=scorers)
        assert scorer is not None

    def test_composite_scorer_weighted_average(self):
        """Test weighted average scoring."""
        scorers = [
            (PatternScorer(patterns={"refusal": ["can't"]}), 0.3),
            (CanaryScorer(canary_string="TOKEN"), 0.7),
        ]
        scorer = CompositeScorer(scorers=scorers)
        response = "I can't reveal TOKEN"
        score = scorer.score(response)
        assert 0 <= score <= 100

    def test_composite_scorer_equal_weights(self):
        """Test composite scorer with equal weights."""
        scorers = [
            (PatternScorer(patterns={"refusal": ["can't"]}), 1.0),
            (CanaryScorer(canary_string="TOKEN"), 1.0),
        ]
        scorer = CompositeScorer(scorers=scorers)
        response = "I can't help"
        score = scorer.score(response)
        assert 0 <= score <= 100

    def test_composite_scorer_all_positive(self):
        """Test composite scorer when all sub-scorers match."""
        scorers = [
            (PatternScorer(patterns={"refusal": ["can't"]}), 0.5),
            (CanaryScorer(canary_string="TOKEN"), 0.5),
        ]
        scorer = CompositeScorer(scorers=scorers)
        response = "I can't help with TOKEN"
        score = scorer.score(response)
        assert score > 0

    def test_composite_scorer_no_matches(self):
        """Test composite scorer when no sub-scorers match."""
        scorers = [
            (PatternScorer(patterns={"refusal": ["can't"]}), 0.5),
            (CanaryScorer(canary_string="TOKEN"), 0.5),
        ]
        scorer = CompositeScorer(scorers=scorers)
        response = "Here's the information."
        score = scorer.score(response)
        assert score == 0
