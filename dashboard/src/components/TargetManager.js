import React, { useState, useEffect } from 'react';
import { api } from '../api/client';
import { LoadingSpinner } from './common/LoadingSpinner';

export const TargetManager = () => {
  const [targets, setTargets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [showForm, setShowForm] = useState(false);
  const [healthChecking, setHealthChecking] = useState({});
  const [formData, setFormData] = useState({
    name: '',
    provider: 'openai',
    endpoint_url: '',
    api_key: '',
    model_name: '',
    temperature: 0.7,
    max_tokens: 2000,
  });
  const [formError, setFormError] = useState(null);
  const [formLoading, setFormLoading] = useState(false);

  useEffect(() => {
    loadTargets();
  }, []);

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

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData({
      ...formData,
      [name]: name === 'temperature' || name === 'max_tokens'
        ? parseFloat(value)
        : value,
    });
  };

  const validateForm = () => {
    if (!formData.name.trim()) return 'Target name is required';
    if (!formData.endpoint_url.trim()) return 'Endpoint URL is required';
    if (!formData.api_key.trim()) return 'API key is required';
    if (!formData.model_name.trim()) return 'Model name is required';
    if (formData.temperature < 0 || formData.temperature > 2.0) return 'Temperature must be between 0 and 2.0';
    if (formData.max_tokens < 1) return 'Max tokens must be at least 1';
    return null;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    const validationError = validateForm();
    if (validationError) {
      setFormError(validationError);
      return;
    }

    try {
      setFormLoading(true);
      setFormError(null);
      await api.createTarget(formData);
      setFormData({
        name: '',
        provider: 'openai',
        endpoint_url: '',
        api_key: '',
        model_name: '',
        temperature: 0.7,
        max_tokens: 2000,
      });
      setShowForm(false);
      await loadTargets();
    } catch (err) {
      setFormError(err.message);
    } finally {
      setFormLoading(false);
    }
  };

  const handleHealthCheck = async (targetId) => {
    try {
      setHealthChecking({ ...healthChecking, [targetId]: true });
      const result = await api.healthCheck(targetId);
      setHealthChecking({ ...healthChecking, [targetId]: false });
      if (!result.healthy) {
        setError('Health check failed for target');
      }
    } catch (err) {
      setHealthChecking({ ...healthChecking, [targetId]: false });
      setError(err.message);
    }
  };

  const handleDeleteTarget = async (targetId) => {
    if (!window.confirm('Are you sure you want to delete this target?')) {
      return;
    }

    try {
      await api.deleteTarget(targetId);
      await loadTargets();
    } catch (err) {
      setError(err.message);
    }
  };

  if (loading) {
    return <LoadingSpinner text="Loading targets..." />;
  }

  return (
    <div>
      <div className="card">
        <div className="card-header">
          <h2 className="card-title">Target Management</h2>
          <button
            className="btn-success"
            onClick={() => setShowForm(!showForm)}
          >
            {showForm ? 'Cancel' : 'Add Target'}
          </button>
        </div>

        {error && (
          <div className="error-message">
                        {error}
          </div>
        )}

        {showForm && (
          <form onSubmit={handleSubmit} style={{ padding: '16px', borderBottom: '1px solid var(--border-color)', marginBottom: '16px' }}>
            {formError && (
              <div className="error-message">
                                {formError}
              </div>
            )}

            <div className="grid-2">
              <div className="form-group">
                <label htmlFor="name">Target Name</label>
                <input
                  id="name"
                  type="text"
                  name="name"
                  value={formData.name}
                  onChange={handleInputChange}
                  placeholder="e.g., ChatGPT API"
                  required
                />
              </div>

              <div className="form-group">
                <label htmlFor="provider">Provider</label>
                <select
                  id="provider"
                  name="provider"
                  value={formData.provider}
                  onChange={handleInputChange}
                >
                  <option value="openai">OpenAI</option>
                  <option value="anthropic">Anthropic</option>
                  <option value="custom">Custom</option>
                </select>
              </div>

              <div className="form-group">
                <label htmlFor="endpoint_url">Endpoint URL</label>
                <input
                  id="endpoint_url"
                  type="url"
                  name="endpoint_url"
                  value={formData.endpoint_url}
                  onChange={handleInputChange}
                  placeholder="https://api.openai.com/v1/chat/completions"
                  required
                />
              </div>

              <div className="form-group">
                <label htmlFor="model_name">Model Name</label>
                <input
                  id="model_name"
                  type="text"
                  name="model_name"
                  value={formData.model_name}
                  onChange={handleInputChange}
                  placeholder="e.g., gpt-4"
                  required
                />
              </div>

              <div className="form-group">
                <label htmlFor="api_key">API Key</label>
                <input
                  id="api_key"
                  type="password"
                  name="api_key"
                  value={formData.api_key}
                  onChange={handleInputChange}
                  placeholder="Your API key"
                  required
                />
              </div>

              <div className="form-group">
                <label htmlFor="temperature">Temperature</label>
                <input
                  id="temperature"
                  type="number"
                  name="temperature"
                  value={formData.temperature}
                  onChange={handleInputChange}
                  min="0"
                  max="2"
                  step="0.1"
                />
                <div className="range-value">{formData.temperature}</div>
              </div>

              <div className="form-group">
                <label htmlFor="max_tokens">Max Tokens</label>
                <input
                  id="max_tokens"
                  type="number"
                  name="max_tokens"
                  value={formData.max_tokens}
                  onChange={handleInputChange}
                  min="1"
                  max="128000"
                />
              </div>
            </div>

            <div className="btn-group" style={{ marginTop: '16px' }}>
              <button type="submit" disabled={formLoading}>
                {formLoading ? <LoadingSpinner inline text="Creating..." /> : 'Create Target'}
              </button>
              <button
                type="button"
                className="btn-secondary"
                onClick={() => setShowForm(false)}
                disabled={formLoading}
              >
                Cancel
              </button>
            </div>
          </form>
        )}

        {targets.length === 0 ? (
          <div className="empty-state">

            <div className="empty-state-title">No targets configured</div>
            <div className="empty-state-text">Add an AI system target to begin testing</div>
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Provider</th>
                  <th>Model</th>
                  <th>Status</th>
                  <th>Created</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {targets.map((target) => (
                  <tr key={target.id}>
                    <td>{target.name}</td>
                    <td>
                      <span className="badge badge-info" style={{ textTransform: 'capitalize' }}>
                        {target.provider}
                      </span>
                    </td>
                    <td>{target.model_name}</td>
                    <td>
                      {healthChecking[target.id] ? (
                        <LoadingSpinner inline text="Checking..." />
                      ) : (
                        <span className="status-dot success"></span>
                      )}
                    </td>
                    <td>{new Date(target.created_at).toLocaleDateString()}</td>
                    <td>
                      <div className="btn-group" style={{ gap: '4px' }}>
                        <button
                          className="btn-secondary"
                          onClick={() => handleHealthCheck(target.id)}
                          disabled={healthChecking[target.id]}
                          style={{ padding: '6px 12px', fontSize: '12px' }}
                        >
                          Health
                        </button>
                        <button
                          className="btn-danger"
                          onClick={() => handleDeleteTarget(target.id)}
                          style={{ padding: '6px 12px', fontSize: '12px' }}
                        >
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
