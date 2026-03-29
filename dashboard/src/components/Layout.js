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
          <p className="sidebar-title">Agentic AI Security Testing</p>
        </div>
        <nav className="sidebar-nav">
          <Link
            to="/"
            className={`nav-item ${isActive('/') && location.pathname === '/' ? 'active' : ''}`}
          >
            Dashboard
          </Link>
          <Link
            to="/targets"
            className={`nav-item ${isActive('/targets') ? 'active' : ''}`}
          >
            Targets
          </Link>
          <Link
            to="/tests"
            className={`nav-item ${isActive('/tests') && !location.pathname.match(/\/tests\/[^\/]+/) ? 'active' : ''}`}
          >
            Run Tests
          </Link>
          <Link
            to="/attacks"
            className={`nav-item ${isActive('/attacks') ? 'active' : ''}`}
          >
            Attack Modules
          </Link>
        </nav>
      </div>
      <div className="main-content">
        <div className="top-bar">
          <h1 className="top-bar-title">Agentic AI Security Testing</h1>
        </div>
        <div className="content">
          {children}
        </div>
      </div>
    </div>
  );
};
