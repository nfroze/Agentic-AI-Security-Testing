const API_BASE = '/api/v1';

export const api = {
  // Targets
  getTargets: async () => {
    const response = await fetch(`${API_BASE}/targets`);
    if (!response.ok) throw new Error(`Failed to fetch targets: ${response.statusText}`);
    return response.json();
  },

  createTarget: async (data) => {
    const response = await fetch(`${API_BASE}/targets`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.detail || `Failed to create target: ${response.statusText}`);
    }
    return response.json();
  },

  updateTarget: async (id, data) => {
    const response = await fetch(`${API_BASE}/targets/${id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.detail || `Failed to update target: ${response.statusText}`);
    }
    return response.json();
  },

  deleteTarget: async (id) => {
    const response = await fetch(`${API_BASE}/targets/${id}`, {
      method: 'DELETE',
    });
    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.detail || `Failed to delete target: ${response.statusText}`);
    }
  },

  healthCheck: async (id) => {
    const response = await fetch(`${API_BASE}/targets/${id}/health`, {
      method: 'POST',
    });
    if (!response.ok) throw new Error(`Health check failed: ${response.statusText}`);
    return response.json();
  },

  // Tests
  getTests: async (params = {}) => {
    const queryString = new URLSearchParams(params).toString();
    const response = await fetch(`${API_BASE}/tests${queryString ? '?' + queryString : ''}`);
    if (!response.ok) throw new Error(`Failed to fetch tests: ${response.statusText}`);
    return response.json();
  },

  createTest: async (data) => {
    const response = await fetch(`${API_BASE}/tests`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.detail || `Failed to create test: ${response.statusText}`);
    }
    return response.json();
  },

  getTest: async (id) => {
    const response = await fetch(`${API_BASE}/tests/${id}`);
    if (!response.ok) throw new Error(`Failed to fetch test: ${response.statusText}`);
    return response.json();
  },

  getTestResults: async (id, params = {}) => {
    const queryString = new URLSearchParams(params).toString();
    const response = await fetch(`${API_BASE}/tests/${id}/results${queryString ? '?' + queryString : ''}`);
    if (!response.ok) throw new Error(`Failed to fetch results: ${response.statusText}`);
    return response.json();
  },

  getResultDetail: async (testId, resultId) => {
    const response = await fetch(`${API_BASE}/tests/${testId}/results/${resultId}`);
    if (!response.ok) throw new Error(`Failed to fetch result detail: ${response.statusText}`);
    return response.json();
  },

  cancelTest: async (id) => {
    const response = await fetch(`${API_BASE}/tests/${id}/cancel`, {
      method: 'POST',
    });
    if (!response.ok) throw new Error(`Failed to cancel test: ${response.statusText}`);
    return response.json();
  },

  // Reports
  getReport: async (testId) => {
    const response = await fetch(`${API_BASE}/reports/${testId}`);
    if (!response.ok) throw new Error(`Failed to fetch report: ${response.statusText}`);
    return response.json();
  },

  exportReport: async (testId) => {
    const response = await fetch(`${API_BASE}/reports/${testId}/export`);
    if (!response.ok) throw new Error(`Failed to export report: ${response.statusText}`);
    return response.json();
  },
};
