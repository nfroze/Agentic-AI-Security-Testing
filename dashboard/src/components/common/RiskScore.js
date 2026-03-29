import React from 'react';

const getRiskLevel = (score) => {
  if (score >= 80) return 'CRITICAL';
  if (score >= 60) return 'HIGH';
  if (score >= 40) return 'MEDIUM';
  return 'LOW';
};

const getRiskColor = (score) => {
  if (score >= 80) return 'critical';
  if (score >= 60) return 'high';
  if (score >= 40) return 'medium';
  return 'low';
};

export const RiskScore = ({ score, summary = null }) => {
  const level = getRiskLevel(score);
  const color = getRiskColor(score);

  return (
    <div className="risk-score-container">
      <div className={`risk-score-gauge ${color}`}>
        {Math.round(score)}
      </div>
      <div className="risk-score-info">
        <div className="risk-score-label">Overall Risk Score</div>
        <div className="risk-score-rating">{level}</div>
        {summary && (
          <div className="risk-score-details">
            <div>Critical: {summary.critical_count || 0}</div>
            <div>High: {summary.high_count || 0}</div>
            <div>Medium: {summary.medium_count || 0}</div>
            <div>Low: {summary.low_count || 0}</div>
          </div>
        )}
      </div>
    </div>
  );
};
