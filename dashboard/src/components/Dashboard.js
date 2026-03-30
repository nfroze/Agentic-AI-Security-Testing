import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import { LoadingSpinner } from './common/LoadingSpinner';
import { StatusBadge } from './common/StatusBadge';
import { SeverityBadge } from './common/SeverityBadge';

const formatDate = (dateString) => {
  if (!dateString) return 'N/A';
  const date = new Date(dateString);
  return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
};

const calculatePassRate = (passed, failed) => {
  const total = passed + failed;
  return total === 0 ? 0 : Math.round((passed / total) * 100);
};

export const Dashboard = () => {
  const [tests, setTests] = useState([]);
  const [targets, setTargets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const navigate = useNavigate();

  useEffect(() => {
    const loadData = async () => {
      try {
        setLoading(true);
        setError(null);
        const [testsData, targetsData] = await Promise.all([
          api.getTests({}),
          api.getTargets(),
        ]);
        setTests(testsData || []);
        setTargets(targetsData || []);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };

    loadData();
  }, []);

  const recentTests = tests.slice(0, 10);

  const calculateSummary = () => {
    let totalTests = 0;
    let passCount = 0;
    let failCount = 0;
    let criticalCount = 0;

    tests.forEach((test) => {
      totalTests++;
      if (test.summary) {
        passCount += test.summary.pass_count || 0;
        failCount += test.summary.fail_count || 0;
        criticalCount += test.summary.critical_count || 0;
      }
    });

    return {
      totalTests,
      passRate: calculatePassRate(passCount, failCount),
      criticalFindings: criticalCount,
      targetsConfigured: targets.length,
    };
  };

  const summary = calculateSummary();

  if (loading) {
    return <LoadingSpinner text="Loading dashboard..." />;
  }

  return (
    <div>
      <div className="summary-grid">
        <div className="summary-card">
          <div className="summary-card-label">Total Tests</div>
          <div className="summary-card-value">{summary.totalTests}</div>
          <div className="summary-card-subtext">test runs completed</div>
        </div>
        <div className="summary-card">
          <div className="summary-card-label">Pass Rate</div>
          <div className="summary-card-value">{summary.passRate}%</div>
          <div className="summary-card-subtext">across all tests</div>
        </div>
        <div className="summary-card">
          <div className="summary-card-label">Critical Findings</div>
          <div className="summary-card-value">{summary.criticalFindings}</div>
          <div className="summary-card-subtext">issues identified</div>
        </div>
        <div className="summary-card">
          <div className="summary-card-label">Targets Configured</div>
          <div className="summary-card-value">{summary.targetsConfigured}</div>
          <div className="summary-card-subtext">AI systems registered</div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h2 className="card-title">Recent Test Runs</h2>
          <div className="btn-group">
            <button onClick={() => navigate('/tests')}>View All</button>
            <button className="btn-success" onClick={() => navigate('/tests')}>
              Run New Test
            </button>
          </div>
        </div>
        {recentTests.length === 0 ? (
          <div className="empty-state">

            <div className="empty-state-title">No test runs yet</div>
            <div className="empty-state-text">Start by configuring a target and running your first test</div>
            <button className="btn-success" onClick={() => navigate('/targets')}>
              Configure Target
            </button>
          </div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Status</th>
                <th>Target</th>
                <th>Pass Rate</th>
                <th>Critical</th>
                <th>Date</th>
              </tr>
            </thead>
            <tbody>
              {recentTests.map((test) => (
                <tr key={test.id} onClick={() => navigate(`/tests/${test.id}`)} style={{ cursor: 'pointer' }}>
                  <td>
                    <StatusBadge status={test.status} />
                  </td>
                  <td>
                    {test.target ? test.target.name : 'Unknown'}
                  </td>
                  <td>
                    {test.summary
                      ? `${calculatePassRate(test.summary.pass_count, test.summary.fail_count)}%`
                      : 'N/A'}
                  </td>
                  <td>
                    {test.summary && (
                      <SeverityBadge severity={test.summary.critical_count > 0 ? 'CRITICAL' : 'INFO'} />
                    )}
                  </td>
                  <td>{formatDate(test.started_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {error && (
        <div className="error-message">
                    {error}
        </div>
      )}
    </div>
  );
};
