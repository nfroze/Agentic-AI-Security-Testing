import React from 'react';
import { Link, useLocation } from 'react-router-dom';

export const Layout = ({ children }) => {
  const location = useLocation();

  const isActive = (path) => {
    if (path === '/') {
      return location.pathname === '/';
    }
    return location.pathname.startsWith(path);
  };

  return (
    <div className="layout">
      <div className="sidebar">
        <div className="sidebar-header">
          <p className="sidebar-title">AAST</p>
          <p style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '10px', color: '#444', marginTop: '4px', marginBottom: 0, letterSpacing: '0.5px' }}>Agentic AI Security Testing</p>
        </div>
        <nav className="sidebar-nav">
          <Link
            to="/"
            className={`nav-item ${isActive('/') && location.pathname === '/' ? 'active' : ''}`}
          >
            <span style={{ opacity: 0.4, marginRight: '8px' }}>01</span> Dashboard
          </Link>
          <Link
            to="/targets"
            className={`nav-item ${isActive('/targets') ? 'active' : ''}`}
          >
            <span style={{ opacity: 0.4, marginRight: '8px' }}>02</span> Targets
          </Link>
          <Link
            to="/tests"
            className={`nav-item ${isActive('/tests') && !location.pathname.match(/\/tests\/[^\/]+/) ? 'active' : ''}`}
          >
            <span style={{ opacity: 0.4, marginRight: '8px' }}>03</span> Run Tests
          </Link>
          <Link
            to="/attacks"
            className={`nav-item ${isActive('/attacks') ? 'active' : ''}`}
          >
            <span style={{ opacity: 0.4, marginRight: '8px' }}>04</span> Attack Modules
          </Link>
        </nav>
      </div>
      <div className="main-content">
        <div className="top-bar">
          <h1 className="top-bar-title">Agentic AI Security Testing</h1>
          <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '11px', color: '#333', letterSpacing: '0.5px' }}>v1.0.0</span>
        </div>
        <div className="content">
          {children}
        </div>
      </div>
    </div>
  );
};
