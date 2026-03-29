import React from 'react';

export const StatusBadge = ({ status }) => {
  const normalizedStatus = (status || 'PENDING').toUpperCase();
  const classNameMap = {
    PENDING: 'badge-pending',
    RUNNING: 'badge-running',
    COMPLETED: 'badge-success',
    FAILED: 'badge-failed',
    CANCELLED: 'badge-pending',
  };

  const className = classNameMap[normalizedStatus] || 'badge-pending';

  return (
    <span className={`badge ${className}`}>
      {normalizedStatus}
    </span>
  );
};
