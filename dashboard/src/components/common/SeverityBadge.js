import React from 'react';

export const SeverityBadge = ({ severity, size = 'default' }) => {
  const normalizedSeverity = (severity || 'INFO').toUpperCase();
  const classNameMap = {
    CRITICAL: 'badge-critical',
    HIGH: 'badge-high',
    MEDIUM: 'badge-medium',
    LOW: 'badge-low',
    INFO: 'badge-info',
  };

  const className = classNameMap[normalizedSeverity] || 'badge-info';

  return (
    <span className={`badge ${className}`}>
      {normalizedSeverity}
    </span>
  );
};
