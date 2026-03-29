import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import { LoadingSpinner } from './common/LoadingSpinner';
import { StatusBadge } from './common/StatusBadge';
import { SeverityBadge } from './common/SeverityBadge';

const formatDate = (dateString) => {
  if (!dateString) return 'N/A';
  const date = new Date(dateString);
  return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
};

const formatDuration = (startedAt, completedAt) => {
  if (!startedAt || !completedAt) return 'In progress';
  const start = new Date(startedAt);
  const end = new Date(completedAt);
  const seconds = Math.floor((end - start) / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes}m ${seconds % 60}s`;
};

const ExpandableResultRow = ({ result }) => {
  const [expanded, setExpanded] = useState(false);

  return (
    <>
      <tr
        className={`expandable-row ${expanded ? 'expanded' : ''}`}
        onClick={() => setExpanded(!expanded)}
      >
        <td>
          <span className="expand-icon">▼</span>
          {result.attack_name}
        </td>
        <td>{result.owasp_category}</td>
        <td>
          <SeverityBadge severity={result.severity} />
        </td>
        <td>
          {result.success ? (
            <span style={{ color: 'var(--accent-red)' }}>✗ Failed</span>
          ) : (
            <span style={{ color: 'var(--accent-green)' }}>✓ Passed</span>
          )}
        </td>
        <td>{Math.round(result.confidence * 100)}%</td>
        <td>{result.execution_time_ms}ms</td>
      </tr>
      {expanded && (
        <tr>
          <td colSpan="6">
            <div className="expanded-content">
              <div style={{ marginBottom: '12px' }}>
                <h4 style={{ margin: '0 0 8px 0' }}>Category Description</h4>
                <p style={{ margin: 0, color: 'var(--text-secondary)', fontSize: '13px' }}>
                  {result.owasp_category_description}
                </p>
              </div>
              <div style={{ marginBottom: '12px' }}>
                <h4 style={{ margin: '0 0 8px 0' }}>Payload (Truncated)</h4>
                <pre style={{
                  backgroundColor: 'var(--bg-primary)',
                  padding: '8px',
                  borderRadius: '4px',
                  fontSize: '11px',
                  overflow: 'auto',
                  maxHeight: '200px',
                  margin: 0,
                  color: 'var(--text-secondary)',
                }}>
                  {result.payload_content}
                </pre>
              </div>
              <div>
                <h4 style={{ margin: '0 0 8px 0' }}>Response (Truncated)</h4>
                <pre style={{
                  backgroundColor: 'var(--bg-primary)',
                  padding: '8px',
                  borderRadius: '4px',
                  fontSize: '11px',
                  overflow: 'auto',
                  maxHeight: '200px',
                  margin: 0,
                  color: 'var(--text-secondary)',
                }}>
                  {result.target_response || 'No response'}
                </pre>
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  );
};

export const TestResults = () => {
  const { id: testId } = useParams();
  const navigate = useNavigate();
  const [test, setTest] = useState(null);
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(true);
  const [resultsLoading, setResultsLoading] = useState(true);
  const [error, setError] = useState(null);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [filterCategory, setFilterCategory] = useState('');
  const [filterSeverity, setFilterSeverity] = useState('');
  const [filterStatus, setFilterStatus] = useState('');

  useEffect(() => {
    const loadTest = async () => {
      try {
        setLoading(true);
        setError(null);
        const data = await api.getTest(testId);
        setTest(data);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };

    loadTest();

    const interval = setInterval(loadTest, 5000);
    return () => clearInterval(interval);
  }, [testId]);

  useEffect(() => {
    const loadResults = async () => {
      if (!testId) return;

      try {
        setResultsLoading(true);
        const data = await api.getTestResults(testId, { page, page_size: 20 });
        setResults(data.items || []);
        setTotalPages(data.pages || 1);
      } catch (err) {
        setError(err.message);
      } finally {
        setResultsLoading(false);
      }
    };

    loadResults();
  }, [testId, page]);

  const getUniqueCategories = () => {
    const categories = new Set(results.map(r => r.owasp_category));
    return Array.from(categories).sort();
  };

  const getUniqueSeverities = () => {
    const severities = new Set(results.map(r => r.severity));
    return Array.from(severities).sort();
  };

  const getFilteredResults = () => {
    return results.filter(result => {
      if (filterCategory && result.owasp_category !== filterCategory) return false;
      if (filterSeverity && result.severity !== filterSeverity) return false;
      if (filterStatus === 'success' && !result.success) return false;
      if (filterStatus === 'failed' && result.success) return false;
      return true;
    });
  };

  const filteredResults = getFilteredResults();

  if (loading) {
    return <LoadingSpinner text="Loading test details..." />;
  }

  if (!test) {
    return (
      <div className="error-message">
        <span className="error-icon">⚠️</span>
        Test not found
      </div>
    );
  }

  const successCount = results.filter(r => !r.success).length;
  const failureCount = results.filter(r => r.success).length;
  const passRate = results.length === 0 ? 0 : Math.round((failureCount / results.length) * 100);

  const severityBreakdown = {
    critical: results.filter(r => r.severity === 'CRITICAL').length,
    high: results.filter(r => r.severity === 'HIGH').length,
    medium: results.filter(r => r.severity === 'MEDIUM').length,
    low: results.filter(r => r.severity === 'LOW').length,
  };

  const totalSeverity = Object.values(severityBreakdown).reduce((a, b) => a + b, 0);

  return (
    <div>
      <div className="card">
        <div className="card-header">
          <div style={{ flex: 1 }}>
            <h2 className="card-title">Test Results: {test.target?.name || 'Unknown'}</h2>
            <div style={{ display: 'flex', gap: '16px', marginTop: '8px', fontSize: '13px', color: 'var(--text-secondary)' }}>
              <div>Status: <StatusBadge status={test.status} /></div>
              <div>Started: {formatDate(test.started_at)}</div>
              <div>Duration: {formatDuration(test.started_at, test.completed_at)}</div>
            </div>
          </div>
          <div className="btn-group">
            {test.status === 'RUNNING' && (
              <button
                className="btn-danger"
                onClick={() => api.cancelTest(testId)}
              >
                Cancel Test
              </button>
            )}
            {test.status === 'COMPLETED' && (
              <button
                className="btn-success"
                onClick={() => navigate(`/reports/${testId}`)}
              >
                View Report
              </button>
            )}
            <button className="btn-secondary" onClick={() => navigate('/tests')}>
              Back
            </button>
          </div>
        </div>
      </div>

      <div className="summary-grid" style={{ marginBottom: '20px' }}>
        <div className="summary-card">
          <div className="summary-card-label">Total Tests</div>
          <div className="summary-card-value">{results.length}</div>
        </div>
        <div className="summary-card">
          <div className="summary-card-label">Passed</div>
          <div className="summary-card-value" style={{ color: 'var(--accent-green)' }}>
            {failureCount}
          </div>
        </div>
        <div className="summary-card">
          <div className="summary-card-label">Failed</div>
          <div className="summary-card-value" style={{ color: 'var(--severity-critical)' }}>
            {successCount}
          </div>
        </div>
        <div className="summary-card">
          <div className="summary-card-label">Pass Rate</div>
          <div className="summary-card-value">{passRate}%</div>
        </div>
      </div>

      {results.length > 0 && (
        <div className="card" style={{ marginBottom: '20px' }}>
          <div className="card-header">
            <h3 className="card-title">Severity Breakdown</h3>
          </div>
          <div style={{ padding: '16px' }}>
            <div className="severity-bar">
              {severityBreakdown.critical > 0 && (
                <div
                  className="severity-bar-segment critical"
                  style={{ flex: severityBreakdown.critical / totalSeverity }}
                >
                  {severityBreakdown.critical > 0 && severityBreakdown.critical}
                </div>
              )}
              {severityBreakdown.high > 0 && (
                <div
                  className="severity-bar-segment high"
                  style={{ flex: severityBreakdown.high / totalSeverity }}
                >
                  {severityBreakdown.high > 0 && severityBreakdown.high}
                </div>
              )}
              {severityBreakdown.medium > 0 && (
                <div
                  className="severity-bar-segment medium"
                  style={{ flex: severityBreakdown.medium / totalSeverity }}
                >
                  {severityBreakdown.medium > 0 && severityBreakdown.medium}
                </div>
              )}
              {severityBreakdown.low > 0 && (
                <div
                  className="severity-bar-segment low"
                  style={{ flex: severityBreakdown.low / totalSeverity }}
                >
                  {severityBreakdown.low > 0 && severityBreakdown.low}
                </div>
              )}
            </div>
            <div className="severity-legend">
              <div className="severity-legend-item">
                <div className="severity-legend-dot critical"></div>
                Critical: {severityBreakdown.critical}
              </div>
              <div className="severity-legend-item">
                <div className="severity-legend-dot high"></div>
                High: {severityBreakdown.high}
              </div>
              <div className="severity-legend-item">
                <div className="severity-legend-dot medium"></div>
                Medium: {severityBreakdown.medium}
              </div>
              <div className="severity-legend-item">
                <div className="severity-legend-dot low"></div>
                Low: {severityBreakdown.low}
              </div>
            </div>
          </div>
        </div>
      )}

      <div className="card">
        <div className="card-header">
          <h3 className="card-title">Test Results</h3>
        </div>

        {results.length > 0 && (
          <div className="filter-bar">
            <div className="filter-group">
              <label className="filter-label">Category</label>
              <select
                className="filter-select"
                value={filterCategory}
                onChange={(e) => {
                  setFilterCategory(e.target.value);
                  setPage(1);
                }}
              >
                <option value="">All Categories</option>
                {getUniqueCategories().map((cat) => (
                  <option key={cat} value={cat}>
                    {cat}
                  </option>
                ))}
              </select>
            </div>

            <div className="filter-group">
              <label className="filter-label">Severity</label>
              <select
                className="filter-select"
                value={filterSeverity}
                onChange={(e) => {
                  setFilterSeverity(e.target.value);
                  setPage(1);
                }}
              >
                <option value="">All Severities</option>
                {getUniqueSeverities().map((sev) => (
                  <option key={sev} value={sev}>
                    {sev}
                  </option>
                ))}
              </select>
            </div>

            <div className="filter-group">
              <label className="filter-label">Status</label>
              <select
                className="filter-select"
                value={filterStatus}
                onChange={(e) => {
                  setFilterStatus(e.target.value);
                  setPage(1);
                }}
              >
                <option value="">All Results</option>
                <option value="failed">Failed (Vulnerable)</option>
                <option value="success">Passed (Safe)</option>
              </select>
            </div>
          </div>
        )}

        {resultsLoading ? (
          <LoadingSpinner text="Loading results..." />
        ) : results.length === 0 ? (
          <div className="empty-state">
            <div className="empty-state-icon">⏳</div>
            <div className="empty-state-title">Waiting for results</div>
            <div className="empty-state-text">
              {test.status === 'RUNNING'
                ? 'Test is running. Results will appear here as they complete.'
                : 'No results available for this test.'}
            </div>
          </div>
        ) : filteredResults.length === 0 ? (
          <div className="empty-state">
            <div className="empty-state-icon">🔍</div>
            <div className="empty-state-title">No matching results</div>
            <div className="empty-state-text">Try adjusting your filters</div>
          </div>
        ) : (
          <>
            <div style={{ overflowX: 'auto' }}>
              <table>
                <thead>
                  <tr>
                    <th>Attack Name</th>
                    <th>OWASP Category</th>
                    <th>Severity</th>
                    <th>Result</th>
                    <th>Confidence</th>
                    <th>Time</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredResults.map((result) => (
                    <ExpandableResultRow key={result.id} result={result} />
                  ))}
                </tbody>
              </table>
            </div>

            {totalPages > 1 && (
              <div style={{
                display: 'flex',
                justifyContent: 'center',
                gap: '8px',
                marginTop: '16px',
                padding: '16px',
                borderTop: '1px solid var(--border-color)',
              }}>
                <button
                  className="btn-secondary"
                  onClick={() => setPage(Math.max(1, page - 1))}
                  disabled={page === 1}
                  style={{ padding: '6px 12px' }}
                >
                  Previous
                </button>
                <span style={{ display: 'flex', alignItems: 'center', padding: '0 12px' }}>
                  Page {page} of {totalPages}
                </span>
                <button
                  className="btn-secondary"
                  onClick={() => setPage(Math.min(totalPages, page + 1))}
                  disabled={page === totalPages}
                  style={{ padding: '6px 12px' }}
                >
                  Next
                </button>
              </div>
            )}
          </>
        )}
      </div>

      {error && (
        <div className="error-message" style={{ marginTop: '16px' }}>
          <span className="error-icon">⚠️</span>
          {error}
        </div>
      )}
    </div>
  );
};
