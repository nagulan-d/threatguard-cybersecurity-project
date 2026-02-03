import React, { useState, useEffect } from 'react';
import '../styles/BlockedThreats.css';

function BlockedThreats() {
  const [blockedThreats, setBlockedThreats] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [showHistory, setShowHistory] = useState(false);

  useEffect(() => {
    fetchBlockedThreats();
  }, [showHistory]);

  const fetchBlockedThreats = async () => {
    setLoading(true);
    setError(null);

    try {
      const token = localStorage.getItem('token');
      const endpoint = showHistory 
        ? 'http://localhost:5000/api/blocked-threats/history'
        : 'http://localhost:5000/api/blocked-threats';

      const response = await fetch(endpoint, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        }
      });

      if (response.status === 401) {
        localStorage.removeItem('token');
        window.location.href = '/login';
        return;
      }

      if (!response.ok) {
        throw new Error(`Failed to fetch blocked threats: ${response.status}`);
      }

      const data = await response.json();
      setBlockedThreats(data.blocked_threats || []);
    } catch (err) {
      console.error('Error fetching blocked threats:', err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleUnblock = async (threatId) => {
    if (!window.confirm('Are you sure you want to unblock this IP address?')) {
      return;
    }

    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`http://localhost:5000/api/unblock-threat/${threatId}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        }
      });

      if (response.ok) {
        alert('IP address successfully unblocked');
        fetchBlockedThreats(); // Refresh list
      } else {
        const data = await response.json();
        alert(`Failed to unblock: ${data.error || 'Unknown error'}`);
      }
    } catch (err) {
      console.error('Error unblocking threat:', err);
      alert('Failed to unblock IP address');
    }
  };

  const getRiskBadgeClass = (category) => {
    switch (category?.toLowerCase()) {
      case 'high':
        return 'risk-badge risk-high';
      case 'medium':
        return 'risk-badge risk-medium';
      case 'low':
        return 'risk-badge risk-low';
      default:
        return 'risk-badge';
    }
  };

  if (loading) {
    return (
      <div className="blocked-threats-container">
        <div className="loading-spinner">
          <div className="spinner"></div>
          <p>Loading blocked threats...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="blocked-threats-container">
      <div className="blocked-threats-header">
        <h2>🛡️ Blocked Threats</h2>
        <div className="header-actions">
          <button 
            className={`toggle-button ${showHistory ? 'active' : ''}`}
            onClick={() => setShowHistory(!showHistory)}
          >
            {showHistory ? 'Show Active Only' : 'Show Full History'}
          </button>
          <button className="refresh-button" onClick={fetchBlockedThreats}>
            🔄 Refresh
          </button>
        </div>
      </div>

      {error && (
        <div className="error-message">
          ⚠️ Error: {error}
        </div>
      )}

      {blockedThreats.length === 0 ? (
        <div className="empty-state">
          <div className="empty-icon">🛡️</div>
          <h3>No Blocked Threats</h3>
          <p>
            {showHistory 
              ? "You haven't blocked any threats yet."
              : "No active blocked threats. All previously blocked threats have been unblocked."}
          </p>
        </div>
      ) : (
        <>
          <div className="threats-count">
            Showing {blockedThreats.length} {showHistory ? 'total' : 'active'} blocked threat(s)
          </div>

          <div className="blocked-threats-grid">
            {blockedThreats.map((threat) => (
              <div key={threat.id} className={`threat-card ${!threat.is_active ? 'inactive' : ''}`}>
                <div className="threat-card-header">
                  <div className="threat-ip">
                    <span className="ip-icon">🌐</span>
                    <code>{threat.ip_address}</code>
                  </div>
                  <span className={getRiskBadgeClass(threat.risk_category)}>
                    {threat.risk_category}
                  </span>
                </div>

                <div className="threat-details">
                  <div className="detail-row">
                    <span className="detail-label">Threat Type:</span>
                    <span className="detail-value">{threat.threat_type}</span>
                  </div>

                  <div className="detail-row">
                    <span className="detail-label">Risk Score:</span>
                    <span className="detail-value score">
                      <div className="score-bar">
                        <div 
                          className="score-fill" 
                          style={{ 
                            width: `${threat.risk_score}%`,
                            backgroundColor: threat.risk_score >= 75 ? '#dc3545' : threat.risk_score >= 50 ? '#ffc107' : '#28a745'
                          }}
                        ></div>
                      </div>
                      {threat.risk_score}/100
                    </span>
                  </div>

                  {threat.summary && (
                    <div className="detail-row">
                      <span className="detail-label">Summary:</span>
                      <span className="detail-value summary">{threat.summary}</span>
                    </div>
                  )}

                  <div className="detail-row">
                    <span className="detail-label">Blocked By:</span>
                    <span className="detail-value">
                      {threat.blocked_by === 'admin' ? '👮 Admin' : '👤 You'}
                    </span>
                  </div>

                  {threat.reason && (
                    <div className="detail-row">
                      <span className="detail-label">Reason:</span>
                      <span className="detail-value">{threat.reason}</span>
                    </div>
                  )}

                  <div className="detail-row">
                    <span className="detail-label">Blocked At:</span>
                    <span className="detail-value">
                      {new Date(threat.blocked_at).toLocaleString()}
                    </span>
                  </div>

                  {threat.unblocked_at && (
                    <div className="detail-row">
                      <span className="detail-label">Unblocked At:</span>
                      <span className="detail-value">
                        {new Date(threat.unblocked_at).toLocaleString()}
                      </span>
                    </div>
                  )}
                </div>

                {threat.is_active && (
                  <div className="threat-actions">
                    <button 
                      className="unblock-button"
                      onClick={() => handleUnblock(threat.id)}
                    >
                      🔓 Unblock IP
                    </button>
                  </div>
                )}

                {!threat.is_active && (
                  <div className="inactive-label">
                    ✅ Unblocked
                  </div>
                )}
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

export default BlockedThreats;
