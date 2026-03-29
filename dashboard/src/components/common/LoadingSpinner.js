import React from 'react';

export const LoadingSpinner = ({ inline = false, text = 'Loading...' }) => {
  if (inline) {
    return (
      <span>
        <span className="spinner" style={{ display: 'inline-block', marginRight: '8px' }}></span>
        {text}
      </span>
    );
  }

  return (
    <div className="loading-container">
      <div className="spinner"></div>
      <span>{text}</span>
    </div>
  );
};
