import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import { LoadingSpinner } from './common/LoadingSpinner';
import { RiskScore } from './common/RiskScore';
import { SeverityBadge } from './common/SeverityBadge';

const formatDate = (dateString) => {
  if (!dateString) return 'N/A';
  const date = new Date(dateString);
  return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
};

const ExpandableFinding = ({ category }) => {
  const [expanded, setExpanded] = useState(false);

  return (
    <div
      style={{
        borderLeft: '4px solid var(--accent-blue)',
        paddingLeft: '16px',
        marginBottom: '16px',
      }}
    >
      <div
        onClick={() => setExpanded(!expanded)}
        style={{
          cursor: 'pointer',
          display: 'flex',
          alignItems: 'center',
          gap: '12px',
          paddingBottom: '12px',
        }}
      >
        <span style={{
          display: 'inline-block',
          transition: 'transform 0.2s',
          transform: expanded ? 'rotate(180deg)' : 'rotate(0deg)',
        }}>
          ▼
        </span>
        <div style={{ flex: 1 }}>
          <h4 style={{ margin: '0 0 4px 0' }}>{category.category_code}: {category.category_name}</h4>
          <p style={{ margin: 0, fontSize: '13px', color: 'var(--text-secondary)' }}>
            {category.category_description}
          </p>
        </div>
      </div>

      {expanded && (
        <div style={{ paddingTop: '12px', borderTop: '1px solid var(--border-color)' }}>
          {category.findings_by_severity.map((finding, idx) => (
            <div key={idx} style={{ marginBottom: '16px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '8px' }}>
                <SeverityBadge severity={finding.severity} />
                <span style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
                  {finding.count} finding{finding.count !== 1 ? 's' : ''}
                </span>
              </div>
              {finding.examples.length > 0 && (
                <ul style={{
                  margin: '8px 0 0 24px',
                  padding: 0,
                  fontSize: '12px',
                  color: 'var(--text-secondary)',
                }}>
                  {finding.examples.slice(0, 3).map((example, exIdx) => (
                    <li key={exIdx} style={{ marginBottom: '4px' }}>
                      {example}
                    </li>
                  ))}
                  {finding.examples.length > 3 && (
                    <li style={{ marginTop: '4px', fontStyle: 'italic' }}>
                      ...and {finding.examples.length - 3} more
                    </li>
                  )}
                </ul>
              )}
            </div>
          ))}

          {category.recommendations.length > 0 && (
            <div style={{
              marginTop: '16px',
              padding: '12px',
              backgroundColor: 'var(--bg-primary)',
              borderRadius: '4px',
            }}>
              <h5 style={{ margin: '0 0 8px 0', color: 'var(--accent-blue)' }}>Recommendations</h5>
              <ul style={{
                margin: 0,
                padding: '0 0 0 20px',
                fontSize: '12px',
                color: 'var(--text-secondary)',
              }}>
                {category.recommendations.map((rec, idx) => (
                  <li key={idx} style={{ marginBottom: '6px' }}>
                    {rec}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export const ReportViewer = () => {
  const { id: testId } = useParams();
  const navigate = useNavigate();
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [exporting, setExporting] = useState(false);

  useEffect(() => {
    const loadReport = async () => {
      try {
        setLoading(true);
        setError(null);
        const data = await api.getReport(testId);
        setReport(data);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };

    loadReport();
  }, [testId]);

  const handleExportJSON = async () => {
    try {
      setExporting(true);
      const data = await api.exportReport(testId);
      const json = JSON.stringify(data, null, 2);
      const blob = new Blob([json], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `report-${testId}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      setError('Failed to export report: ' + err.message);
    } finally {
      setExporting(false);
    }
  };

  const handlePrint = () => {
    window.print();
  };

  if (loading) {
    return <LoadingSpinner text="Generating report..." />;
  }

  if (!report) {
    return (
      <div className="error-message">
        <span className="error-icon">⚠️</span>
        Report not available. Test may still be running.
      </div>
    );
  }

  return (
    <div>
      <div className="card">
        <div className="card-header">
          <div style={{ flex: 1 }}>
            <h2 className="card-title">Security Assessment Report</h2>
            <div style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '8px' }}>
              {report.target_name} • Generated {formatDate(report.generated_at)}
            </div>
          </div>
          <div className="btn-group">
            <button className="btn-secondary" onClick={handlePrint} style={{ display: 'none' }} className="no-print">
              Print
            </button>
            <button
              className="btn-secondary"
              onClick={handleExportJSON}
              disabled={exporting}
            >
              {exporting ? 'Exporting...' : 'Export JSON'}
            </button>
            <button className="btn-secondary" onClick={() => navigate(`/tests/${testId}`)}>
              Back
            </button>
          </div>
        </div>
      </div>

      <RiskScore score={report.risk_score} summary={report.summary} />

      <div className="card" style={{ marginBottom: '20px' }}>
        <div className="card-header">
          <h3 className="card-title">Executive Summary</h3>
        </div>
        <div style={{ padding: '16px' }}>
          <div className="grid-2">
            {report.summary && Object.entries(report.summary).map(([key, value]) => (
              <div key={key} style={{ padding: '12px', backgroundColor: 'var(--bg-tertiary)', borderRadius: '6px' }}>
                <div style={{ fontSize: '12px', textTransform: 'uppercase', letterSpacing: '0.5px', color: 'var(--text-secondary)', marginBottom: '4px' }}>
                  {key.replace(/_/g, ' ')}
                </div>
                <div style={{ fontSize: '24px', fontWeight: 700, color: 'var(--text-primary)' }}>
                  {typeof value === 'number' ? Math.round(value * 100) / 100 : value}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {report.findings_by_category.length > 0 && (
        <div className="card" style={{ marginBottom: '20px' }}>
          <div className="card-header">
            <h3 className="card-title">Findings by OWASP Category</h3>
          </div>
          <div style={{ padding: '16px' }}>
            {report.findings_by_category.map((category, idx) => (
              <ExpandableFinding key={idx} category={category} />
            ))}
          </div>
        </div>
      )}

      {report.recommendations.length > 0 && (
        <div className="card" style={{ marginBottom: '20px' }}>
          <div className="card-header">
            <h3 className="card-title">Remediation Recommendations</h3>
          </div>
          <ol style={{
            padding: '16px 16px 16px 40px',
            margin: 0,
            color: 'var(--text-secondary)',
            fontSize: '14px',
            lineHeight: '1.8',
          }}>
            {report.recommendations.map((rec, idx) => (
              <li key={idx} style={{ marginBottom: '12px' }}>
                {rec}
              </li>
            ))}
          </ol>
        </div>
      )}

      {error && (
        <div className="error-message">
          <span className="error-icon">⚠️</span>
          {error}
        </div>
      )}
    </div>
  );
};
