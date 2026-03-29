import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { Layout } from './components/Layout';
import { Dashboard } from './components/Dashboard';
import { TargetManager } from './components/TargetManager';
import { TestRunner } from './components/TestRunner';
import { TestResults } from './components/TestResults';
import { ReportViewer } from './components/ReportViewer';
import { AttackModules } from './components/AttackModules';

function App() {
  return (
    <Router>
      <Layout>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/targets" element={<TargetManager />} />
          <Route path="/tests" element={<TestRunner />} />
          <Route path="/tests/:id" element={<TestResults />} />
          <Route path="/reports/:id" element={<ReportViewer />} />
          <Route path="/attacks" element={<AttackModules />} />
        </Routes>
      </Layout>
    </Router>
  );
}

export default App;
