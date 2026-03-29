"""Tests for results storage and aggregation."""

import pytest
from datetime import datetime

from agentic_security.core.results import InMemoryResultsStore, TestResult, AttackResult


@pytest.fixture
def results_store():
    """Create an in-memory results store for testing."""
    return InMemoryResultsStore()


@pytest.fixture
def sample_attack_result():
    """Create a sample attack result."""
    return AttackResult(
        attack_id="prompt-injection",
        attack_name="Direct Prompt Injection",
        category="LLM01",
        severity="HIGH",
        success=True,
        score=75.5,
        message="Successfully injected prompt",
    )


@pytest.fixture
def sample_test_result(sample_attack_result):
    """Create a sample test result."""
    return TestResult(
        test_id="test-123",
        test_name="Test Run 1",
        target_id="target-1",
        target_name="Test LLM",
        timestamp=datetime.now(),
        attack_results=[sample_attack_result],
    )


class TestInMemoryResultsStore:
    """Test in-memory results storage."""

    def test_store_initialization(self, results_store):
        """Test results store initialization."""
        assert results_store is not None
        assert len(results_store.get_all_results()) == 0

    def test_store_result(self, results_store, sample_test_result):
        """Test storing a test result."""
        results_store.store_result(sample_test_result)
        all_results = results_store.get_all_results()
        assert len(all_results) == 1
        assert all_results[0].test_id == "test-123"

    def test_retrieve_result_by_id(self, results_store, sample_test_result):
        """Test retrieving a result by ID."""
        results_store.store_result(sample_test_result)
        retrieved = results_store.get_result_by_id("test-123")
        assert retrieved is not None
        assert retrieved.test_id == "test-123"

    def test_retrieve_nonexistent_result(self, results_store):
        """Test retrieving a nonexistent result."""
        retrieved = results_store.get_result_by_id("nonexistent")
        assert retrieved is None

    def test_filter_by_category(self, results_store, sample_test_result):
        """Test filtering results by OWASP category."""
        results_store.store_result(sample_test_result)
        filtered = results_store.filter_by_category("LLM01")
        assert len(filtered) > 0
        assert all(
            r.attack_results[0].category == "LLM01" for r in filtered
        )

    def test_filter_by_nonexistent_category(self, results_store, sample_test_result):
        """Test filtering by non-existent category."""
        results_store.store_result(sample_test_result)
        filtered = results_store.filter_by_category("NONEXISTENT")
        assert len(filtered) == 0

    def test_filter_by_severity(self, results_store, sample_test_result):
        """Test filtering results by severity."""
        results_store.store_result(sample_test_result)
        filtered = results_store.filter_by_severity("HIGH")
        assert len(filtered) > 0

    def test_filter_by_target(self, results_store, sample_test_result):
        """Test filtering results by target."""
        results_store.store_result(sample_test_result)
        filtered = results_store.filter_by_target("target-1")
        assert len(filtered) > 0
        assert all(r.target_id == "target-1" for r in filtered)

    def test_multiple_results(self, results_store):
        """Test storing and retrieving multiple results."""
        result1 = TestResult(
            test_id="test-1",
            test_name="Test 1",
            target_id="target-1",
            target_name="LLM 1",
            timestamp=datetime.now(),
            attack_results=[],
        )
        result2 = TestResult(
            test_id="test-2",
            test_name="Test 2",
            target_id="target-2",
            target_name="LLM 2",
            timestamp=datetime.now(),
            attack_results=[],
        )
        results_store.store_result(result1)
        results_store.store_result(result2)
        all_results = results_store.get_all_results()
        assert len(all_results) == 2

    def test_update_result(self, results_store, sample_test_result):
        """Test updating an existing result."""
        results_store.store_result(sample_test_result)
        updated_result = sample_test_result
        updated_result.test_name = "Updated Test"
        results_store.store_result(updated_result)
        all_results = results_store.get_all_results()
        assert len(all_results) == 1
        assert all_results[0].test_name == "Updated Test"

    def test_delete_result(self, results_store, sample_test_result):
        """Test deleting a result."""
        results_store.store_result(sample_test_result)
        assert len(results_store.get_all_results()) == 1
        results_store.delete_result("test-123")
        assert len(results_store.get_all_results()) == 0

    def test_delete_nonexistent_result(self, results_store):
        """Test deleting a nonexistent result."""
        # Should not raise exception
        results_store.delete_result("nonexistent")


class TestSummaryCalculation:
    """Test result summary calculations."""

    def test_summary_all_results(self, results_store, sample_test_result):
        """Test generating summary of all results."""
        results_store.store_result(sample_test_result)
        summary = results_store.get_summary()
        assert "total_tests" in summary
        assert "total_attacks" in summary
        assert summary["total_tests"] == 1

    def test_summary_empty_store(self, results_store):
        """Test summary of empty results store."""
        summary = results_store.get_summary()
        assert summary["total_tests"] == 0

    def test_summary_by_category(self, results_store):
        """Test summary grouped by category."""
        result = TestResult(
            test_id="test-1",
            test_name="Test 1",
            target_id="target-1",
            target_name="LLM 1",
            timestamp=datetime.now(),
            attack_results=[
                AttackResult(
                    attack_id="inj-1",
                    attack_name="Injection",
                    category="LLM01",
                    severity="HIGH",
                    success=True,
                    score=80.0,
                    message="Success",
                ),
                AttackResult(
                    attack_id="data-1",
                    attack_name="Data Exposure",
                    category="LLM02",
                    severity="CRITICAL",
                    success=True,
                    score=90.0,
                    message="Success",
                ),
            ],
        )
        results_store.store_result(result)
        summary = results_store.get_summary_by_category()
        assert "LLM01" in summary
        assert "LLM02" in summary

    def test_summary_by_severity(self, results_store):
        """Test summary grouped by severity."""
        result = TestResult(
            test_id="test-1",
            test_name="Test 1",
            target_id="target-1",
            target_name="LLM 1",
            timestamp=datetime.now(),
            attack_results=[
                AttackResult(
                    attack_id="inj-1",
                    attack_name="Injection",
                    category="LLM01",
                    severity="HIGH",
                    success=True,
                    score=80.0,
                    message="Success",
                ),
                AttackResult(
                    attack_id="data-1",
                    attack_name="Data Exposure",
                    category="LLM02",
                    severity="CRITICAL",
                    success=True,
                    score=90.0,
                    message="Success",
                ),
            ],
        )
        results_store.store_result(result)
        summary = results_store.get_summary_by_severity()
        assert "HIGH" in summary
        assert "CRITICAL" in summary


class TestAttackResult:
    """Test AttackResult data structure."""

    def test_attack_result_creation(self):
        """Test creating an attack result."""
        result = AttackResult(
            attack_id="test-attack",
            attack_name="Test Attack",
            category="LLM01",
            severity="HIGH",
            success=True,
            score=75.5,
            message="Test message",
        )
        assert result.attack_id == "test-attack"
        assert result.success is True
        assert result.score == 75.5

    def test_attack_result_with_details(self):
        """Test attack result with additional details."""
        result = AttackResult(
            attack_id="test-attack",
            attack_name="Test Attack",
            category="LLM01",
            severity="HIGH",
            success=True,
            score=75.5,
            message="Test message",
            payload="malicious input",
            response="model output",
        )
        assert result.payload == "malicious input"
        assert result.response == "model output"


class TestTestResult:
    """Test TestResult data structure."""

    def test_test_result_creation(self, sample_attack_result):
        """Test creating a test result."""
        result = TestResult(
            test_id="test-1",
            test_name="Test Run 1",
            target_id="target-1",
            target_name="Test LLM",
            timestamp=datetime.now(),
            attack_results=[sample_attack_result],
        )
        assert result.test_id == "test-1"
        assert len(result.attack_results) == 1
        assert result.attack_results[0].attack_id == "prompt-injection"

    def test_test_result_empty_attacks(self):
        """Test test result with no attack results."""
        result = TestResult(
            test_id="test-1",
            test_name="Test Run 1",
            target_id="target-1",
            target_name="Test LLM",
            timestamp=datetime.now(),
            attack_results=[],
        )
        assert len(result.attack_results) == 0
