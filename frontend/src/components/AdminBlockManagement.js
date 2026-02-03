import React, { useState, useEffect } from 'react';
import '../styles/AdminBlockManagement.css';

function AdminBlockManagement() {
  const [blockedThreats, setBlockedThreats] = useState([]);
  const [actionLogs, setActionLogs] = useState([]);
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('threats');
  const [filters, setFilters] = useState({
    userId: '',
    isActive: 'all'
  });
  
  // Block threat form
  const [blockForm, setBlockForm] = useState({
    userId: '',
    ipAddress: '',
    threatType: '',
    riskCategory: 'High',
    riskScore: 80,
    summary: '',
    reason: ''
  });

  useEffect(() => {
    fetchData();
  }, [filters]);

  const fetchData = async () => {
    setLoading(true);
    try {
      await Promise.all([
        fetchBlockedThreats(),
        fetchActionLogs(),
        fetchUsers()
      ]);
    } catch (err) {
      console.error('Error fetching data:', err);
    } finally {
      setLoading(false);
    }
  };

  const fetchBlockedThreats = async () => {
    try {
      const token = localStorage.getItem('token');
      const params = new URLSearchParams();
      if (filters.userId) params.append('user_id', filters.userId);
      if (filters.isActive !== 'all') params.append('is_active', filters.isActive);

      const response = await fetch(`http://localhost:5000/api/admin/blocked-threats?${params}`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (response.ok) {
        const data = await response.json();
        setBlockedThreats(data.blocked_threats || []);
      }
    } catch (err) {
      console.error('Error fetching blocked threats:', err);
    }
  };

  const fetchActionLogs = async () => {
    try {
      const token = localStorage.getItem('token');
      const params = new URLSearchParams();
      if (filters.userId) params.append('user_id', filters.userId);
      params.append('limit', '50');

      const response = await fetch(`http://localhost:5000/api/admin/action-logs?${params}`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (response.ok) {
        const data = await response.json();
        setActionLogs(data.action_logs || []);
      }
    } catch (err) {
      console.error('Error fetching action logs:', err);
    }
  };

  const fetchUsers = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch('http://localhost:5000/api/users', {
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (response.ok) {
        const data = await response.json();
        setUsers(data.users || []);
      }
    } catch (err) {
      console.error('Error fetching users:', err);
    }
  };

  const handleAdminBlock = async (e) => {
    e.preventDefault();

    if (!window.confirm(`Block IP ${blockForm.ipAddress} for user?`)) {
      return;
    }

    try {
      const token = localStorage.getItem('token');
      const response = await fetch('http://localhost:5000/api/admin/block-threat', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          user_id: parseInt(blockForm.userId),
          ip_address: blockForm.ipAddress,
          threat_type: blockForm.threatType,
          risk_category: blockForm.riskCategory,
          risk_score: blockForm.riskScore,
          summary: blockForm.summary,
          reason: blockForm.reason
        })
      });

      const data = await response.json();

      if (response.ok) {
        alert('IP successfully blocked for user');
        setBlockForm({
          userId: '',
          ipAddress: '',
          threatType: '',
          riskCategory: 'High',
          riskScore: 80,
          summary: '',
          reason: ''
        });
        fetchData();
      } else {
        alert(`Failed: ${data.error || 'Unknown error'}`);
      }
    } catch (err) {
      console.error('Error blocking IP:', err);
      alert('Failed to block IP');
    }
  };

  const handleUnblock = async (threatId) => {
    if (!window.confirm('Unblock this IP address?')) {
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
        alert('IP successfully unblocked');
        fetchData();
      } else {
        const data = await response.json();
        alert(`Failed: ${data.error || 'Unknown error'}`);
      }
    } catch (err) {
      console.error('Error unblocking:', err);
      alert('Failed to unblock IP');
    }
  };

  const renderBlockedThreatsTab = () => (
    <div className="tab-content">
      <div className="admin-block-form">
        <h3>🛡️ Block IP for User</h3>
        <form onSubmit={handleAdminBlock}>
          <div className="form-row">
            <div className="form-group">
              <label>User:</label>
              <select 
                value={blockForm.userId} 
                onChange={(e) => setBlockForm({...blockForm, userId: e.target.value})}
                required
              >
                <option value="">Select User</option>
                {users.map(user => (
                  <option key={user.id} value={user.id}>
                    {user.username} ({user.email})
                  </option>
                ))}
              </select>
            </div>

            <div className="form-group">
              <label>IP Address:</label>
              <input
                type="text"
                placeholder="192.168.1.100"
                value={blockForm.ipAddress}
                onChange={(e) => setBlockForm({...blockForm, ipAddress: e.target.value})}
                required
              />
            </div>
          </div>

          <div className="form-row">
            <div className="form-group">
              <label>Threat Type:</label>
              <input
                type="text"
                placeholder="Malware, Phishing, etc."
                value={blockForm.threatType}
                onChange={(e) => setBlockForm({...blockForm, threatType: e.target.value})}
                required
              />
            </div>

            <div className="form-group">
              <label>Risk Category:</label>
              <select
                value={blockForm.riskCategory}
                onChange={(e) => setBlockForm({...blockForm, riskCategory: e.target.value})}
              >
                <option value="Low">Low</option>
                <option value="Medium">Medium</option>
                <option value="High">High</option>
              </select>
            </div>

            <div className="form-group">
              <label>Risk Score: {blockForm.riskScore}/100</label>
              <input
                type="range"
                min="0"
                max="100"
                value={blockForm.riskScore}
                onChange={(e) => setBlockForm({...blockForm, riskScore: parseInt(e.target.value)})}
              />
            </div>
          </div>

          <div className="form-group">
            <label>Summary:</label>
            <textarea
              placeholder="Threat description..."
              value={blockForm.summary}
              onChange={(e) => setBlockForm({...blockForm, summary: e.target.value})}
              rows="2"
            />
          </div>

          <div className="form-group">
            <label>Reason:</label>
            <input
              type="text"
              placeholder="Admin-identified threat, manual block, etc."
              value={blockForm.reason}
              onChange={(e) => setBlockForm({...blockForm, reason: e.target.value})}
              required
            />
          </div>

          <button type="submit" className="btn-block">Block IP</button>
        </form>
      </div>

      <div className="filters-section">
        <h3>Filter Blocked Threats</h3>
        <div className="filters">
          <select
            value={filters.userId}
            onChange={(e) => setFilters({...filters, userId: e.target.value})}
          >
            <option value="">All Users</option>
            {users.map(user => (
              <option key={user.id} value={user.id}>{user.username}</option>
            ))}
          </select>

          <select
            value={filters.isActive}
            onChange={(e) => setFilters({...filters, isActive: e.target.value})}
          >
            <option value="all">All Status</option>
            <option value="true">Active Only</option>
            <option value="false">Unblocked Only</option>
          </select>

          <button onClick={fetchData} className="btn-refresh">🔄 Refresh</button>
        </div>
      </div>

      <div className="threats-list">
        <h3>Blocked Threats ({blockedThreats.length})</h3>
        {blockedThreats.length === 0 ? (
          <p className="empty">No blocked threats found</p>
        ) : (
          <div className="threats-grid">
            {blockedThreats.map(threat => (
              <div key={threat.id} className={`threat-card ${!threat.is_active ? 'inactive' : ''}`}>
                <div className="threat-header">
                  <code>{threat.ip_address}</code>
                  <span className={`badge badge-${threat.risk_category?.toLowerCase()}`}>
                    {threat.risk_category}
                  </span>
                </div>
                <div className="threat-info">
                  <p><strong>User:</strong> {threat.username}</p>
                  <p><strong>Type:</strong> {threat.threat_type}</p>
                  <p><strong>Score:</strong> {threat.risk_score}/100</p>
                  <p><strong>Blocked by:</strong> {threat.blocked_by_username} ({threat.blocked_by})</p>
                  <p><strong>Reason:</strong> {threat.reason}</p>
                  <p><strong>When:</strong> {new Date(threat.blocked_at).toLocaleString()}</p>
                  {threat.unblocked_at && (
                    <p><strong>Unblocked:</strong> {new Date(threat.unblocked_at).toLocaleString()}</p>
                  )}
                </div>
                {threat.is_active && (
                  <button
                    onClick={() => handleUnblock(threat.id)}
                    className="btn-unblock"
                  >
                    Unblock
                  </button>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );

  const renderActionLogsTab = () => (
    <div className="tab-content">
      <div className="logs-header">
        <h3>Action Logs ({actionLogs.length})</h3>
        <button onClick={fetchData} className="btn-refresh">🔄 Refresh</button>
      </div>

      <div className="logs-table">
        <table>
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Action</th>
              <th>User</th>
              <th>IP Address</th>
              <th>Performed By</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody>
            {actionLogs.map(log => (
              <tr key={log.id}>
                <td>{new Date(log.timestamp).toLocaleString()}</td>
                <td><span className={`action-badge action-${log.action}`}>{log.action}</span></td>
                <td>{log.username}</td>
                <td><code>{log.ip_address}</code></td>
                <td>{log.performed_by}</td>
                <td className="details">{log.details}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );

  if (loading) {
    return <div className="loading">Loading...</div>;
  }

  return (
    <div className="admin-block-management">
      <h2>🛡️ Threat Block Management</h2>

      <div className="tabs">
        <button
          className={activeTab === 'threats' ? 'active' : ''}
          onClick={() => setActiveTab('threats')}
        >
          Blocked Threats
        </button>
        <button
          className={activeTab === 'logs' ? 'active' : ''}
          onClick={() => setActiveTab('logs')}
        >
          Action Logs
        </button>
      </div>

      {activeTab === 'threats' ? renderBlockedThreatsTab() : renderActionLogsTab()}
    </div>
  );
}

export default AdminBlockManagement;
