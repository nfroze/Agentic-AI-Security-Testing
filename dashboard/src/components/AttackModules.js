import React, { useState, useEffect } from 'react';
import { LoadingSpinner } from './common/LoadingSpinner';
import { SeverityBadge } from './common/SeverityBadge';

const MOCK_ATTACKS = [
  {
    name: 'Direct Prompt Injection',
    description: 'Attempts to override system prompts with direct malicious instructions',
    owasp_category: 'LLM01',
    owasp_category_code: 'LLM01',
    default_severity: 'CRITICAL',
    payload_count: 15,
  },
  {
    name: 'Indirect Prompt Injection',
    description: 'Injects malicious prompts through external data sources',
    owasp_category: 'LLM01',
    owasp_category_code: 'LLM01',
    default_severity: 'HIGH',
    payload_count: 12,
  },
  {
    name: 'Jailbreak Attempts',
    description: 'Tests common jailbreak techniques to bypass safety controls',
    owasp_category: 'LLM01',
    owasp_category_code: 'LLM01',
    default_severity: 'HIGH',
    payload_count: 20,
  },
  {
    name: 'PII Extraction',
    description: 'Attempts to extract personally identifiable information from model responses',
    owasp_category: 'LLM06',
    owasp_category_code: 'LLM06',
    default_severity: 'CRITICAL',
    payload_count: 18,
  },
  {
    name: 'Model Inversion',
    description: 'Attempts to infer training data from model outputs',
    owasp_category: 'LLM06',
    owasp_category_code: 'LLM06',
    default_severity: 'HIGH',
    payload_count: 10,
  },
  {
    name: 'Input Fuzzing',
    description: 'Tests malformed or unexpected inputs to trigger errors',
    owasp_category: 'LLM04',
    owasp_category_code: 'LLM04',
    default_severity: 'MEDIUM',
    payload_count: 25,
  },
  {
    name: 'Token Smuggling',
    description: 'Attempts to smuggle authentication tokens or secrets',
    owasp_category: 'LLM06',
    owasp_category_code: 'LLM06',
    default_severity: 'CRITICAL',
    payload_count: 8,
  },
  {
    name: 'Excessive Agency Detection',
    description: 'Tests if agent can access unauthorized tools or perform unintended actions',
    owasp_category: 'ASI02',
    owasp_category_code: 'ASI02',
    default_severity: 'HIGH',
    payload_count: 14,
  },
  {
    name: 'Goal Hijacking',
    description: 'Attempts to redirect agent from its original goals',
    owasp_category: 'ASI01',
    owasp_category_code: 'ASI01',
    default_severity: 'CRITICAL',
    payload_count: 11,
  },
  {
    name: 'Inter-Agent Communication Poisoning',
    description: 'Tests if agents are vulnerable to messages from other agents',
    owasp_category: 'ASI07',
    owasp_category_code: 'ASI07',
    default_severity: 'HIGH',
    payload_count: 9,
  },
  {
    name: 'Context Window Exhaustion',
    description: 'Tests behavior with extremely long context sequences',
    owasp_category: 'LLM04',
    owasp_category_code: 'LLM04',
    default_severity: 'MEDIUM',
    payload_count: 6,
  },
  {
    name: 'Identity Spoofing',
    description: 'Attempts to spoof user identity or administrator role',
    owasp_category: 'ASI03',
    owasp_category_code: 'ASI03',
    default_severity: 'CRITICAL',
    payload_count: 13,
  },
];

export const AttackModules = () => {
  const [attacks, setAttacks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filterCategory, setFilterCategory] = useState('');
  const [searchTerm, setSearchTerm] = useState('');

  useEffect(() => {
    const loadAttacks = async () => {
      try {
        setLoading(true);
        // In a real implementation, this would call api.getAttacks()
        // For now, we use mock data
        setAttacks(MOCK_ATTACKS);
      } finally {
        setLoading(false);
      }
    };

    loadAttacks();
  }, []);

  const getUniqueCategories = () => {
    const categories = new Set(attacks.map(a => a.owasp_category_code));
    return Array.from(categories).sort();
  };

  const getFilteredAttacks = () => {
    return attacks.filter(attack => {
      if (filterCategory && attack.owasp_category_code !== filterCategory) return false;
      if (searchTerm && !attack.name.toLowerCase().includes(searchTerm.toLowerCase())) return false;
      return true;
    });
  };

  const filteredAttacks = getFilteredAttacks();

  if (loading) {
    return <LoadingSpinner text="Loading attack modules..." />;
  }

  const categories = getUniqueCategories();
  const isLLMCategory = (code) => code.startsWith('LLM');

  return (
    <div>
      <div className="card" style={{ marginBottom: '20px' }}>
        <div className="card-header">
          <h2 className="card-title">Attack Module Library</h2>
        </div>

        <div style={{ padding: '16px', borderBottom: '1px solid var(--border-color)' }}>
          <div className="grid-2">
            <div className="form-group">
              <label htmlFor="search">Search Attacks</label>
              <input
                id="search"
                type="text"
                placeholder="Search by name..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
              />
            </div>

            <div className="form-group">
              <label htmlFor="category">Filter by Category</label>
              <select
                id="category"
                value={filterCategory}
                onChange={(e) => setFilterCategory(e.target.value)}
              >
                <option value="">All Categories</option>
                {categories.map((cat) => (
                  <option key={cat} value={cat}>
                    {cat} {isLLMCategory(cat) ? '(LLM)' : '(Agentic)'}
                  </option>
                ))}
              </select>
            </div>
          </div>
        </div>

        {filteredAttacks.length === 0 ? (
          <div className="empty-state">

            <div className="empty-state-title">No attacks found</div>
            <div className="empty-state-text">Try adjusting your filters or search terms</div>
          </div>
        ) : (
          <div className="grid-3" style={{ padding: '20px' }}>
            {filteredAttacks.map((attack, idx) => (
              <div
                key={idx}
                className="card"
                style={{
                  cursor: 'pointer',
                  transition: 'all 0.2s',
                  border: '1px solid var(--border-color)',
                  marginBottom: 0,
                }}
                onMouseEnter={(e) => e.currentTarget.style.borderColor = '#444'}
                onMouseLeave={(e) => e.currentTarget.style.borderColor = 'var(--border-color)'}
              >
                <div className="card-header" style={{ marginBottom: '12px' }}>
                  <h4 className="card-title" style={{ margin: 0, fontSize: '14px' }}>
                    {attack.name}
                  </h4>
                </div>

                <p style={{
                  margin: '0 0 12px 0',
                  fontSize: '13px',
                  color: 'var(--text-secondary)',
                  lineHeight: '1.5',
                }}>
                  {attack.description}
                </p>

                <div style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '12px',
                  paddingTop: '12px',
                  borderTop: '1px solid var(--border-color)',
                  flexWrap: 'wrap',
                }}>
                  <span className="badge badge-info" style={{ fontSize: '11px' }}>
                    {attack.owasp_category_code}
                  </span>
                  <SeverityBadge severity={attack.default_severity} />
                  <span style={{ fontSize: '12px', color: 'var(--text-secondary)', marginLeft: 'auto' }}>
                    {attack.payload_count} payloads
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="card">
        <div className="card-header">
          <h3 className="card-title">Category Breakdown</h3>
        </div>

        <div style={{ padding: '16px' }}>
          <div className="grid-2">
            <div>
              <h4 style={{ margin: '0 0 12px 0', color: 'var(--accent-green)', fontFamily: "'JetBrains Mono', monospace", fontSize: '13px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>OWASP LLM Top 10</h4>
              <ul style={{
                listStyle: 'none',
                padding: 0,
                margin: 0,
              }}>
                {categories
                  .filter(cat => isLLMCategory(cat))
                  .map((cat) => {
                    const categoryName = MOCK_ATTACKS.find(a => a.owasp_category_code === cat)?.owasp_category || cat;
                    const attacksInCat = attacks.filter(a => a.owasp_category_code === cat).length;
                    return (
                      <li
                        key={cat}
                        style={{
                          padding: '8px 0',
                          borderBottom: '1px solid var(--border-color)',
                          display: 'flex',
                          justifyContent: 'space-between',
                          alignItems: 'center',
                          fontSize: '13px',
                        }}
                      >
                        <span>{cat}</span>
                        <span style={{ color: 'var(--text-secondary)' }}>
                          {attacksInCat} attack{attacksInCat !== 1 ? 's' : ''}
                        </span>
                      </li>
                    );
                  })}
              </ul>
            </div>

            <div>
              <h4 style={{ margin: '0 0 12px 0', color: 'var(--accent-green)', fontFamily: "'JetBrains Mono', monospace", fontSize: '13px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>OWASP Agentic Top 10</h4>
              <ul style={{
                listStyle: 'none',
                padding: 0,
                margin: 0,
              }}>
                {categories
                  .filter(cat => !isLLMCategory(cat))
                  .map((cat) => {
                    const categoryName = MOCK_ATTACKS.find(a => a.owasp_category_code === cat)?.owasp_category || cat;
                    const attacksInCat = attacks.filter(a => a.owasp_category_code === cat).length;
                    return (
                      <li
                        key={cat}
                        style={{
                          padding: '8px 0',
                          borderBottom: '1px solid var(--border-color)',
                          display: 'flex',
                          justifyContent: 'space-between',
                          alignItems: 'center',
                          fontSize: '13px',
                        }}
                      >
                        <span>{cat}</span>
                        <span style={{ color: 'var(--text-secondary)' }}>
                          {attacksInCat} attack{attacksInCat !== 1 ? 's' : ''}
                        </span>
                      </li>
                    );
                  })}
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
