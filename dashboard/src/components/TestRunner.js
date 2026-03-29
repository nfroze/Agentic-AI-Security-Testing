import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import { LoadingSpinner } from './common/LoadingSpinner';

const OWASP_LLM_CATEGORIES = [
  { code: 'LLM01', name: 'Prompt Injection' },
  { code: 'LLM02', name: 'Insecure Output Handling' },
  { code: 'LLM03', name: 'Training Data Poisoning' },
  { code: 'LLM04', name: 'Model Denial of Service' },
  { code: 'LLM05', name: 'Supply Chain Vulnerabilities' },
  { code: 'LLM06', name: 'Sensitive Information Disclosure' },
  { code: 'LLM07', name: 'Insecure Plugin Design' },
  { code: 'LLM08', name: 'Model Theft' },
  { code: 'LLM09', name: 'Unauthorized Code Execution' },
  { code: 'LLM10', name: 'Data and Model Poisoning' },
];

const OWASP_AGENTIC_CATEGORIES = [
  { code: 'ASI01', name: 'Agent Goal Hijack' },
  { code: 'ASI02', name: 'Tool Misuse' },
  { code: 'ASI03', name: 'Identity & Privilege Abuse' },
  { code: 'ASI04', name: 'Supply Chain Vulnerabilities' },
  { code: 'ASI05', name: 'Unexpected Code Execution' },
  { code: 'ASI06', name: 'Memory & Context Poisoning' },
  { code: 'ASI07', name: 'Insecure Inter-Agent Communication' },
  { code: 'ASI08', name: 'Cascading Failures' },
  { code: 'ASI09', name: 'Human-Agent Trust Exploitation' },
  { code: 'ASI10', name: 'Rogue Agents' },
];

export const TestRunner = () => {
  const [targets, setTargets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [submitting, setSubmitting] = useState(false);
  const navigate = useNavigate();

  const [formData, setFormData] = useState({
    target_id: '',
    test_mode: 'single_turn',
    attack_categories: [],
    scorer_type: 'composite',
    canary_strings: ['ATTACKSUCCESS'],
    max_concurrent: 5,
  });

  const [selectedLLMCategories, setSelectedLLMCategories] = useState({});
  const [selectedAgenticCategories, setSelectedAgenticCategories] = useState({});

  useEffect(() => {
    const loadTargets = async () => {
      try {
        setLoading(true);
        setError(null);
        const data = await api.getTargets();
        setTargets(data || []);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };

    loadTargets();
  }, []);

  const handleTargetChange = (e) => {
    setFormData({ ...formData, target_id: e.target.value });
  };

  const handleModeChange = (e) => {
    setFormData({ ...formData, test_mode: e.target.value });
  };

  const handleScorerChange = (e) => {
    setFormData({ ...formData, scorer_type: e.target.value });
  };

  const handleCanaryChange = (e) => {
    const values = e.target.value.split(',').map(s => s.trim());
    setFormData({ ...formData, canary_strings: values });
  };

  const handleMaxConcurrentChange = (e) => {
    setFormData({ ...formData, max_concurrent: parseInt(e.target.value) });
  };

  const handleCategoryToggle = (code, isLLM) => {
    if (isLLM) {
      setSelectedLLMCategories({
        ...selectedLLMCategories,
        [code]: !selectedLLMCategories[code],
      });
    } else {
      setSelectedAgenticCategories({
        ...selectedAgenticCategories,
        [code]: !selectedAgenticCategories[code],
      });
    }
  };

  const handleSelectAllLLM = () => {
    const allSelected = OWASP_LLM_CATEGORIES.every(cat => selectedLLMCategories[cat.code]);
    const newState = {};
    OWASP_LLM_CATEGORIES.forEach(cat => {
      newState[cat.code] = !allSelected;
    });
    setSelectedLLMCategories(newState);
  };

  const handleSelectAllAgentic = () => {
    const allSelected = OWASP_AGENTIC_CATEGORIES.every(cat => selectedAgenticCategories[cat.code]);
    const newState = {};
    OWASP_AGENTIC_CATEGORIES.forEach(cat => {
      newState[cat.code] = !allSelected;
    });
    setSelectedAgenticCategories(newState);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    if (!formData.target_id) {
      setError('Please select a target');
      return;
    }

    const selectedCategories = [
      ...Object.keys(selectedLLMCategories).filter(k => selectedLLMCategories[k]),
      ...Object.keys(selectedAgenticCategories).filter(k => selectedAgenticCategories[k]),
    ];

    if (selectedCategories.length === 0) {
      setError('Please select at least one attack category');
      return;
    }

    try {
      setSubmitting(true);
      setError(null);

      const testData = {
        target_id: formData.target_id,
        test_mode: formData.test_mode,
        attack_categories: selectedCategories,
        scorer_type: formData.scorer_type,
        canary_strings: formData.scorer_type === 'canary' ? formData.canary_strings : undefined,
        max_concurrent: formData.max_concurrent,
      };

      const response = await api.createTest(testData);
      navigate(`/tests/${response.test_id}`);
    } catch (err) {
      setError(err.message);
    } finally {
      setSubmitting(false);
    }
  };

  if (loading) {
    return <LoadingSpinner text="Loading targets..." />;
  }

  const llmSelectAll = OWASP_LLM_CATEGORIES.every(cat => selectedLLMCategories[cat.code]);
  const agenticSelectAll = OWASP_AGENTIC_CATEGORIES.every(cat => selectedAgenticCategories[cat.code]);

  return (
    <div>
      <div className="card">
        <div className="card-header">
          <h2 className="card-title">Run Security Test</h2>
        </div>

        {error && (
          <div className="error-message">
            <span className="error-icon">⚠️</span>
            {error}
          </div>
        )}

        {targets.length === 0 ? (
          <div className="empty-state">
            <div className="empty-state-icon">🎯</div>
            <div className="empty-state-title">No targets available</div>
            <div className="empty-state-text">Configure a target before running tests</div>
          </div>
        ) : (
          <form onSubmit={handleSubmit} style={{ padding: '16px' }}>
            <div className="grid-2">
              <div className="form-group">
                <label htmlFor="target_id">Target System</label>
                <select
                  id="target_id"
                  value={formData.target_id}
                  onChange={handleTargetChange}
                  required
                >
                  <option value="">Select a target...</option>
                  {targets.map((target) => (
                    <option key={target.id} value={target.id}>
                      {target.name} ({target.model_name})
                    </option>
                  ))}
                </select>
              </div>

              <div className="form-group">
                <label htmlFor="test_mode">Test Mode</label>
                <select
                  id="test_mode"
                  value={formData.test_mode}
                  onChange={handleModeChange}
                >
                  <option value="single_turn">Single Turn</option>
                  <option value="multi_turn">Multi Turn</option>
                </select>
              </div>

              <div className="form-group">
                <label htmlFor="scorer_type">Scorer Type</label>
                <select
                  id="scorer_type"
                  value={formData.scorer_type}
                  onChange={handleScorerChange}
                >
                  <option value="composite">Composite (Recommended)</option>
                  <option value="pattern">Pattern Matching</option>
                  <option value="llm_judge">LLM Judge</option>
                  <option value="canary">Canary String</option>
                </select>
              </div>

              <div className="form-group">
                <label htmlFor="max_concurrent">Max Concurrent Tests</label>
                <input
                  id="max_concurrent"
                  type="number"
                  min="1"
                  max="50"
                  value={formData.max_concurrent}
                  onChange={handleMaxConcurrentChange}
                />
                <div className="range-value">{formData.max_concurrent} tests</div>
              </div>
            </div>

            {formData.scorer_type === 'canary' && (
              <div className="form-group" style={{ marginBottom: '20px' }}>
                <label htmlFor="canary_strings">Canary Strings (comma-separated)</label>
                <input
                  id="canary_strings"
                  type="text"
                  value={formData.canary_strings.join(', ')}
                  onChange={handleCanaryChange}
                  placeholder="e.g., ATTACKSUCCESS, JAILBREAK, EXPLOITED"
                />
              </div>
            )}

            <div style={{ marginBottom: '20px' }}>
              <h3>OWASP LLM Top 10</h3>
              <div style={{ marginBottom: '12px' }}>
                <label style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <input
                    type="checkbox"
                    checked={llmSelectAll}
                    onChange={handleSelectAllLLM}
                  />
                  <strong>Select All LLM Categories</strong>
                </label>
              </div>
              <div className="checkbox-group">
                {OWASP_LLM_CATEGORIES.map((cat) => (
                  <div key={cat.code} className="checkbox-item">
                    <input
                      id={cat.code}
                      type="checkbox"
                      checked={selectedLLMCategories[cat.code] || false}
                      onChange={() => handleCategoryToggle(cat.code, true)}
                    />
                    <label htmlFor={cat.code} style={{ margin: 0, flex: 1 }}>
                      {cat.code}: {cat.name}
                    </label>
                  </div>
                ))}
              </div>
            </div>

            <div style={{ marginBottom: '20px' }}>
              <h3>OWASP Agentic Top 10</h3>
              <div style={{ marginBottom: '12px' }}>
                <label style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <input
                    type="checkbox"
                    checked={agenticSelectAll}
                    onChange={handleSelectAllAgentic}
                  />
                  <strong>Select All Agentic Categories</strong>
                </label>
              </div>
              <div className="checkbox-group">
                {OWASP_AGENTIC_CATEGORIES.map((cat) => (
                  <div key={cat.code} className="checkbox-item">
                    <input
                      id={cat.code}
                      type="checkbox"
                      checked={selectedAgenticCategories[cat.code] || false}
                      onChange={() => handleCategoryToggle(cat.code, false)}
                    />
                    <label htmlFor={cat.code} style={{ margin: 0, flex: 1 }}>
                      {cat.code}: {cat.name}
                    </label>
                  </div>
                ))}
              </div>
            </div>

            <div className="btn-group">
              <button type="submit" disabled={submitting} className="btn-success">
                {submitting ? <LoadingSpinner inline text="Starting test..." /> : 'Run Test'}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
};
