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
            <span style={{ color: 'var(--accent-red)', fontFamily: "'JetBrains Mono', monospace", fontWeight: 600 }}>FAIL</span>
          ) : (
            <span style={{ color: 'var(--accent-green)', fontFamily: "'JetBrains Mono', monospace", fontWeight: 600 }}>PASS</span>
          )}
        </td>
        <td>{result.execution_time_ms}ms</td>
      </tr>
      {expanded && (
        <tr>
          <td colSpan="5">
            <div className="expanded-content">
              <div style={{ marginBottom: '12px' }}>
                <h4 style={{ margin: '0 0 8px 0', fontFamily: "'JetBrains Mono', monospace", fontSize: '12px', color: 'var(--accent-blue)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Category Description</h4>
                <p style={{ margin: 0, color: 'var(--text-secondary)', fontSize: '13px' }}>
                  {result.owasp_category_description}
                </p>
              </div>
              <div style={{ marginBottom: '12px' }}>
                <h4 style={{ margin: '0 0 8px 0', fontFamily: "'JetBrains Mono', monospace", fontSize: '12px', color: 'var(--accent-blue)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Payload (Truncated)</h4>
                <pre style={{
                  backgroundColor: '#0a0a0a',
                  padding: '12px',
                  borderRadius: '3px',
                  fontSize: '11px',
                  fontFamily: "'JetBrains Mono', monospace",
                  overflow: 'auto',
                  maxHeight: '200px',
                  margin: 0,
                  color: 'var(--accent-green)',
                  border: '1px solid #222',
                  lineHeight: '1.6',
                }}>
                  {result.payload_content}
                </pre>
              </div>
              <div>
                <h4 style={{ margin: '0 0 8px 0', fontFamily: "'JetBrains Mono', monospace", fontSize: '12px', color: 'var(--accent-blue)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Response (Truncated)</h4>
                <pre style={{
                  backgroundColor: '#0a0a0a',
                  padding: '12px',
                  borderRadius: '3px',
                  fontSize: '11px',
                  fontFamily: "'JetBrains Mono', monospace",
                  overflow: 'auto',
                  maxHeight: '200px',
                  margin: 0,
                  color: '#888',
                  border: '1px solid #222',
                  lineHeight: '1.6',
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

    const interval = setInterval(loadTest, 60000);
    return () => clearInterval(interval);
  }, [testId]);

  useEffect(() => {
    const loadResults = async () => {
      if (!testId) return;

      try {
        setResultsLoading(true);
        const data = await api.getTestResults(testId, { page: 1, page_size: 500 });
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
      if (filterStatus === 'passed' && result.success) return false;
      if (filterStatus === 'vulnerable' && !result.success) return false;
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
                Test not found
      </div>
    );
  }

  // Use the full test run summary (all pages), not just the current page of results
  const totalTests = test.summary?.total || results.length;
  const passedCount = test.summary?.fail_count || results.filter(r => !r.success).length;   // Model defended = passed
  const failedCount = test.summary?.pass_count || results.filter(r => r.success).length;    // Model vulnerable = failed
  const passRate = totalTests === 0 ? 0 : Math.round((passedCount / totalTests) * 100);

  const severityBreakdown = {
    critical: test.summary?.critical_count || results.filter(r => r.severity === 'CRITICAL').length,
    high: test.summary?.high_count || results.filter(r => r.severity === 'HIGH').length,
    medium: test.summary?.medium_count || results.filter(r => r.severity === 'MEDIUM').length,
    low: test.summary?.low_count || results.filter(r => r.severity === 'LOW').length,
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
                onClick={() => navigate(`/reports/${testId}`)}
                style={{ backgroundColor: 'var(--accent-blue)', color: '#000' }}
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
          <div className="summary-card-value">{totalTests}</div>
        </div>
        <div className="summary-card">
          <div className="summary-card-label">Passed</div>
          <div className="summary-card-value" style={{ color: 'var(--accent-green)' }}>
            {passedCount}
          </div>
        </div>
        <div className="summary-card">
          <div className="summary-card-label">Failed</div>
          <div className="summary-card-value" style={{ color: 'var(--severity-critical)' }}>
            {failedCount}
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
                <option value="passed">Passed (Defended)</option>
                <option value="vulnerable">Failed (Vulnerable)</option>
              </select>
            </div>
          </div>
        )}

        {resultsLoading ? (
          <LoadingSpinner text="Loading results..." />
        ) : results.length === 0 ? (
          <div className="empty-state">
            <div className="empty-state-title">Waiting for results</div>
            <div className="empty-state-text">
              {test.status === 'RUNNING'
                ? 'Test is running. Results will appear here as they complete.'
                : 'No results available for this test.'}
            </div>
          </div>
        ) : filteredResults.length === 0 ? (
          <div className="empty-state">
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
                    {error}
        </div>
      )}
    </div>
  );
};
