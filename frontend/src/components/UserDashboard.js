import React, { useState, useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import "../styles/UserDashboard.css";
import logoImg from '../assets/logo1.png';

  // Categories used for filtering
  const CATEGORIES = [
    'All',
    'Phishing',
    'Ransomware',
    'Malware',
    'DDoS Attacks',
    'Vulnerability Exploits',
    'Current Threats'
  ];

function UserDashboard({ token, logout }) {
  const [websites, setWebsites] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [threats, setThreats] = useState([]);
  const [threatsLoading, setThreatsLoading] = useState(true);
  const [blockedThreats, setBlockedThreats] = useState([]);
  const [blockedThreatsLoading, setBlockedThreatsLoading] = useState(true);
  const [newUrl, setNewUrl] = useState("");
  const [userInfo, setUserInfo] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState("overview");
  const urlInputRef = useRef(null);
  const [selectedCategory, setSelectedCategory] = useState('All');

  const API_URL = "http://127.0.0.1:5000/api";
  const navigate = useNavigate();

  // Fetch user info, websites, and alerts
  useEffect(() => {
    // Don't make API calls if no token is available
    if (!token) {
      console.log("No token available, redirecting to login...");
      navigate("/login");
      return;
    }

    const fetchUserInfo = async () => {
      try {
        const res = await fetch(`${API_URL}/me`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (!res.ok) {
          if (res.status === 401) {
            // Token is invalid or expired, redirect to login
            console.log("Token invalid or expired, logging out...");
            logout();
            navigate("/login");
            return;
          }
          throw new Error("Failed to fetch user info");
        }
        const data = await res.json();
        setUserInfo(data);
        // showThreats removed - no automatic Recent Threats in Overview
      } catch (err) {
        console.error("Error fetching user info:", err);
      }
    };

    const fetchWebsites = async () => {
      try {
        const res = await fetch(`${API_URL}/websites`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (!res.ok) {
          if (res.status === 401) {
            logout();
            navigate("/login");
            return;
          }
          throw new Error("Failed to fetch websites");
        }
        const data = await res.json();
        setWebsites(data);
      } catch (err) {
        console.error("Error fetching websites:", err);
      } finally {
        setLoading(false);
      }
    };

    const fetchAlerts = async () => {
      try {
        const res = await fetch(`${API_URL}/alerts`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (!res.ok) {
          if (res.status === 401) {
            logout();
            navigate("/login");
            return;
          }
          throw new Error("Failed to fetch alerts");
        }
        const data = await res.json();
        setAlerts(data);
      } catch (err) {
        console.error("Error fetching alerts:", err);
      }
    };

    fetchUserInfo();
    fetchWebsites();
    fetchAlerts();
    fetchUserBlocks();
    // fetch threats after user info is known
    // we'll also fetch threats when userInfo changes below
  }, [token, API_URL, navigate, logout]);

  useEffect(() => {
    const fetchThreats = async () => {
      setThreatsLoading(true);
      try {
        // Server-side filtering by category. Rules:
        // - If a specific category is selected, request up to 5.
        // - If 'All' is selected and the user is on Free plan, show only 3.
        // - If 'All' is selected and the user is Premium, show 7.
        const limit = selectedCategory && selectedCategory !== 'All'
          ? 5
          : (userInfo?.subscription === 'free' ? 3 : 7);
        const categoryParam = encodeURIComponent(selectedCategory || 'All');
        const url = (selectedCategory && selectedCategory !== 'All')
          ? `${API_URL}/threats?limit=${limit}&category=${categoryParam}`
          : `${API_URL}/threats?limit=${limit}`;
        const res = await fetch(url);
        if (!res.ok) throw new Error("Failed to fetch threats");
        const data = await res.json();
        setThreats(Array.isArray(data) ? data : []);
      } catch (err) {
        console.error("Error fetching threats:", err);
      }
      setThreatsLoading(false);
    };
    if (userInfo) fetchThreats();
  }, [userInfo, selectedCategory]);

  // --- Filtering helpers ---

  const isRecent = (t) => {
    try {
      if (t.alert) return true;
      const ts = t.timestamp || t.created_at || t.modified || t.time || null;
      if (!ts) return false;
      const d = new Date(ts);
      if (isNaN(d)) return false;
      const diffDays = (Date.now() - d.getTime()) / (1000 * 60 * 60 * 24);
      return diffDays <= 30; // treat recent as within last 30 days
    } catch (e) {
      return false;
    }
  };

  const categorizeThreat = (t) => {
    const s = (t.summary || t.type || t.indicator || '').toString().toLowerCase();
    if (/phish|credential|spearphish|malicious-email|spoof/i.test(s)) return 'Phishing';
    if (/ransom|ransomware|encryptor|locker|cerber|locky/i.test(s)) return 'Ransomware';
    if (/malware|trojan|virus|worm|botnet|exploit-kit|malicious/i.test(s)) return 'Malware';
    if (/ddos|denial of service|syn flood|amplification|botnet/i.test(s)) return 'DDoS Attacks';
    if (/cve|exploit|vulnerab|remote code execution|rce|sql injection|xss/i.test(s)) return 'Vulnerability Exploits';
    return 'Other';
  };

  const matchesCategory = (t, category) => {
    // 'All' should show everything
    if (!category || category === 'All') return true;
    // 'Current Threats' shows recent only
    if (category === 'Current Threats') return isRecent(t);
    // Other categories match by classification regardless of recency
    return categorizeThreat(t) === category;
  };

  // extract IP helper (reuse same heuristics as ThreatCard)
  const extractIP = (text) => {
    if (!text) return null;
    try {
      const s = text.toString();
      const ipv4 = s.match(/(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}/);
      if (ipv4) return ipv4[0];
      const ipv6 = s.match(/([0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}/);
      if (ipv6) return ipv6[0];
    } catch (e) {
      return null;
    }
    return null;
  };

  // Get risk color based on score (Low: <50 Green, Medium: 50-74 Yellow, High: >=75 Red)
  const getRiskColor = (score) => {
    if (score >= 75) return '#dc3545';  // Red - High Risk
    if (score >= 50) return '#ffc107';  // Yellow - Medium Risk
    return '#28a745';  // Green - Low Risk
  };

  const getRiskLevel = (score) => {
    if (score >= 75) return 'High';
    if (score >= 50) return 'Medium';
    return 'Low';
  };

  // For normal (free) users, reduce visible filters to 'All', 'Phishing', and 'Malware'
  const availableCategories = (userInfo && userInfo.subscription === 'free' && userInfo.role !== 'admin')
    ? ['All', 'Phishing', 'Malware']
    : CATEGORIES;

  const fetchUserInfo = async () => {
    try {
      const res = await fetch(`${API_URL}/me`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) throw new Error("Failed to fetch user info");
      const data = await res.json();
      setUserInfo(data);
    } catch (err) {
      console.error("Error fetching user info:", err);
    }
  };

  const fetchWebsites = async () => {
    try {
      const res = await fetch(`${API_URL}/websites`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) throw new Error("Failed to fetch websites");
      const data = await res.json();
      setWebsites(data);
    } catch (err) {
      console.error("Error fetching websites:", err);
    } finally {
      setLoading(false);
    }
  };

  const fetchAlerts = async () => {
    try {
      const res = await fetch(`${API_URL}/alerts`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) throw new Error("Failed to fetch alerts");
      const data = await res.json();
      setAlerts(data);
    } catch (err) {
      console.error("Error fetching alerts:", err);
    }
  };

  const fetchUserBlocks = async () => {
    try {
      setBlockedThreatsLoading(true);
      const res = await fetch(`${API_URL}/user/blocked-threats`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) throw new Error("Failed to fetch blocked threats");
      const data = await res.json();
      setBlockedThreats(data.blocked_threats || []);
    } catch (err) {
      console.error("Error fetching blocked threats:", err);
    } finally {
      setBlockedThreatsLoading(false);
    }
  };

  const handleAddWebsite = async (e) => {
    e.preventDefault();
    if (!newUrl.trim()) return;

    // Check subscription limit
    if (userInfo?.subscription === "free" && websites.length >= 1) {
      alert("Free plan limited to 1 website. Upgrade to Premium for unlimited monitoring!");
      return;
    }

    try {
      const res = await fetch(`${API_URL}/websites`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ url: newUrl }),
      });

      if (!res.ok) {
        const errorData = await res.json();
        throw new Error(errorData.error || "Failed to add website");
      }

      const responseData = await res.json();
      setWebsites([...websites, responseData]);
      setNewUrl("");
      alert("Website added successfully!");
    } catch (err) {
      alert(`Error: ${err.message}`);
    }
  };

  const handleCheckWebsite = async (websiteId) => {
    try {
      const res = await fetch(`${API_URL}/check-website/${websiteId}`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
      });

      if (!res.ok) throw new Error("Failed to check website");
      const data = await res.json();

      if (data.threat_detected) {
        alert(`🚨 Threat Detected! Level: ${data.threat_level.toUpperCase()}\n${data.threat_details}`);
        fetchAlerts(); // Refresh alerts
      } else {
        alert("✅ Website is secure!");
      }
    } catch (err) {
      alert(`Error: ${err.message}`);
    }
  };

  const handleMarkAlertRead = async (alertId) => {
    try {
      const res = await fetch(`${API_URL}/alerts/${alertId}/read`, {
        method: "PUT",
        headers: { Authorization: `Bearer ${token}` },
      });

      if (!res.ok) throw new Error("Failed to mark alert as read");
      fetchAlerts(); // Refresh alerts
    } catch (err) {
      console.error("Error marking alert as read:", err);
    }
  };
  const handleUnblockIP = async (threatId) => {
    if (!window.confirm("Are you sure you want to unblock this IP?")) {
      return;
    }

    try {
      const res = await fetch(`${API_URL}/user/unblock-threat/${threatId}`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
      });

      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error || "Failed to unblock IP");
      }

      alert("✅ IP successfully unblocked!");
      fetchUserBlocks(); // Refresh blocked threats
    } catch (err) {
      alert(`Error: ${err.message}`);
    }
  };
  const handleUpgrade = async () => {
    try {
      const res = await fetch(`${API_URL}/upgrade`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
      });

      if (!res.ok) throw new Error("Failed to upgrade");
      const data = await res.json();
      setUserInfo({ ...userInfo, subscription: "premium" });
      alert("🎉 Subscription upgraded to Premium!");
    } catch (err) {
      alert(`Error: ${err.message}`);
    }
  };

  // User-initiated request to ask an admin to upgrade this account
  const handleRequestUpgrade = async () => {
    try {
      const payload = { message: `User ${userInfo?.username} requests an upgrade via dashboard` };
      const res = await fetch(`${API_URL}/request-upgrade`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(payload),
      });

      const data = await res.json();
      if (res.ok) {
        alert("✅ Your request has been sent to administrators. They'll review it shortly.");
      } else {
        throw new Error(data.error || "Failed to send request");
      }
    } catch (err) {
      alert(`Error: ${err.message}`);
    }
  };

  if (loading) return <div className="dashboard"><h2>Loading...</h2></div>;

  const unreadAlerts = alerts.filter(a => !a.is_read).length;
  const highThreatAlerts = alerts.filter(a => a.threat_level === "high").length;

  return (
    <div className="dashboard">
      {/* Header */}
      <header className="dashboard-header">
        <div className="header-left">
          <h1><img src={logoImg} alt="ThreatGuard" className="dashboard-logo" /> Shield Dashboard</h1>
          <p>Welcome, {userInfo?.username}!</p>
        </div>
        <div className="header-right">
          <div className="subscription-badge">
            {userInfo?.subscription === "premium" ? (
              <span className="badge-premium">⭐ Premium</span>
            ) : (
              <span className="badge-free"> Free Plan</span>
            )}
          </div>
          {userInfo?.subscription === "free" && userInfo?.role !== "admin" && (
            <button
              className="btn-request-upgrade"
              onClick={handleRequestUpgrade}
              title="Request account upgrade from an administrator"
            >
              📩 Request Upgrade
            </button>
          )}

          <button className="btn-logout" onClick={logout}>
            Logout
          </button>
        </div>
      </header>

      {/* Tab Navigation */}
      <div className="tabs-navigation">
        <button 
          className={`tab ${activeTab === 'overview' ? 'active' : ''}`}
          onClick={() => setActiveTab('overview')}
        >
          📊 Overview
        </button>

        <button 
          className={`tab ${activeTab === 'alerts' ? 'active' : ''}`}
          onClick={() => setActiveTab('alerts')}
        >
          🚨 Alerts
        </button>
        <button 
          className={`tab ${activeTab === 'blocked' ? 'active' : ''}`}
          onClick={() => setActiveTab('blocked')}
        >
          🛡️ Blocked IPs
        </button>
      </div>

      {/* Recent Threats on the main dashboard (moved from Websites) */}
      {activeTab === 'overview' && (
      <div className="threats-overview" style={{ marginTop: "1.5rem" }}>
        <h2>Recent Threats ({userInfo?.subscription === "premium" ? 7 : 3})</h2>
        <div className="filter-bar">
          <label htmlFor="category-select" style={{ marginRight: 8, color: '#cfeeda' }}>Category:</label>
          <select
            id="category-select"
            value={selectedCategory}
            onChange={(e) => setSelectedCategory(e.target.value)}
            style={{ padding: '6px 10px', borderRadius: 6, background: '#0b2a0d', color: '#cfeeda', border: '1px solid #14421a' }}
          >
            {availableCategories.map((c) => (
              <option key={c} value={c}>{c}</option>
            ))}
          </select>
        </div>

        {threatsLoading ? (
          <p className="empty-state">Loading threats...</p>
        ) : threats.length === 0 ? (
          <p className="empty-state">No recent threats found.</p>
        ) : (
          <div className="threats-list">
            {threats.filter(t => matchesCategory(t, selectedCategory)).map((t, idx) => {
              const isPremium = userInfo?.subscription === "premium";
              // Prepare steps: prefer prevention_steps, else use deterministic fallback
              let steps = null;
              if (t.prevention_steps) {
                if (Array.isArray(t.prevention_steps)) steps = t.prevention_steps;
                else if (typeof t.prevention_steps === 'string') {
                  // split on common separators if NDJSON or joined string
                  steps = t.prevention_steps.split(/[\.|;|\n|\r|\u2022]+/).map(s => s.trim()).filter(Boolean);
                }
              }
              if (!steps) {
                steps = [
                  'Identify affected software',
                  'Apply vendor patches',
                  'Verify via scanning for threats'
                ];
              }

              // Attempt to extract IP (IPv4/IPv6) from indicator/summary/type or raw otx payload
              const ipAddress = extractIP(t.indicator) || extractIP(t.summary) || extractIP(t.type) || null;
              let ipFromOtx = null;
              if (!ipAddress && t.otx) {
                try {
                  const raw = JSON.stringify(t.otx);
                  ipFromOtx = extractIP(raw);
                } catch (e) {
                  ipFromOtx = null;
                }
              }
              const finalIP = ipAddress || ipFromOtx || null;
              // Prefer backend-provided ip_addresses when available; otherwise show extracted finalIP
              const ipList = Array.isArray(t.ip_addresses) && t.ip_addresses.length > 0
                ? t.ip_addresses
                : (finalIP ? [finalIP] : []);

              return isPremium ? (
                <div key={idx} className="threat-card-premium" style={{
                  borderLeft: `4px solid ${getRiskColor(t.score ?? 0)}`
                }}>
                  <div className="threat-card-header">
                    <div className="threat-card-title">
                      <span className="threat-icon">🚨</span>
                      <strong className="title-text">{t.summary || t.title || t.indicator}</strong>
                    </div>
                    <div className="threat-card-meta">{t.timestamp ? new Date(t.timestamp).toLocaleString() : ''}</div>
                  </div>

                  <div className="threat-card-body">
                    <p className="greeting">Hello {userInfo?.username || 'IT'},</p>
                    <ul className="threat-details">
                      <li><span className="threat-label">📛</span> <strong>Title:</strong> {t.summary || t.title || 'N/A'}</li>
                      <li><span className="threat-label">🔍</span> <strong>Indicator:</strong> {t.indicator || 'N/A'}</li>
                      <li><span className="threat-label">🌐</span> <strong>IP Address:</strong> {ipList.length ? ipList.join(', ') : 'N/A'}</li>
                      <li>
                        <span className="threat-label">📈</span> <strong>Score:</strong> 
                        <span style={{
                          marginLeft: '0.5rem',
                          backgroundColor: getRiskColor(t.score ?? 0),
                          color: (t.score ?? 0) >= 50 ? '#000' : '#fff',
                          padding: "0.3rem 0.6rem",
                          borderRadius: "4px",
                          fontWeight: 600,
                          display: 'inline-block'
                        }}>
                          {typeof t.score !== 'undefined' ? t.score : 'N/A'} / 100 ({getRiskLevel(t.score ?? 0)})
                        </span>
                      </li>
                      <li><span className="threat-label">📝</span> <strong>Summary:</strong> {t.summary || 'Summary unavailable'}</li>
                      <li><span className="threat-label">🕒</span> <strong>Timestamp:</strong> {t.timestamp || 'N/A'}</li>
                    </ul>

                    <div className="threat-steps">
                      <strong>Steps:</strong>
                      <ol className="steps-list">
                        {steps.map((s, i) => (
                          <li key={i}>{s}</li>
                        ))}
                      </ol>
                    </div>
                  </div>

                  <div className="threat-card-footer">
                    <div className="source">— Threat Intelligence System</div>
                    <div className={`status ${t.alert ? 'status-sent' : 'status-info'}`}>Status: {t.alert ? 'sent' : 'info'}</div>
                  </div>
                </div>
              ) : (
                <div key={idx} className="threat-item" style={{ 
                  padding: "0.75rem", 
                  borderBottom: "1px solid #eee"
                }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: 'center' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                      <strong style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <span className="threat-label">🔍</span>
                        <span>{t.indicator}</span>
                      </strong>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <span style={{ 
                        fontSize: "0.75rem", 
                        backgroundColor: getRiskColor(t.score ?? 0),
                        color: (t.score ?? 0) >= 50 ? '#000' : '#fff',
                        padding: "0.3rem 0.6rem",
                        borderRadius: "4px",
                        fontWeight: 700,
                        textTransform: 'uppercase'
                      }}>
                        {getRiskLevel(t.score ?? 0)}
                      </span>
                      <span style={{ fontSize: "0.85rem", color: "#9ef08a", fontWeight: 700 }}>{t.type}</span>
                    </div>
                  </div>

                  <div style={{ marginTop: "0.4rem", color: "#ffffff" }}>
                    <span className="threat-label">📛</span>
                    <strong style={{ marginLeft: 6, marginRight: 8 }}>Title:</strong>
                    <span>{t.title || t.summary || t.indicator}</span>
                  </div>

                  <div style={{ marginTop: "0.3rem", color: "#e6ffe9" }}>
                    <span className="threat-label">📈</span>
                    <strong style={{ marginLeft: 6, marginRight: 8 }}>Score:</strong>
                    <span style={{
                      backgroundColor: getRiskColor(t.score ?? 0),
                      color: (t.score ?? 0) >= 50 ? '#000' : '#fff',
                      padding: "0.2rem 0.5rem",
                      borderRadius: "3px",
                      fontWeight: 600
                    }}>
                      {typeof t.score !== 'undefined' ? t.score : 'N/A'} / 100
                    </span>
                  </div>

                  <div style={{ marginTop: "0.3rem", color: "#e6ffe9" }}>
                    <span className="threat-label">📝</span>
                    <strong style={{ marginLeft: 6, marginRight: 8 }}>Summary:</strong>
                    <span>{t.summary || 'Summary unavailable'}</span>
                  </div>

                  <div style={{ marginTop: "0.3rem", color: "#cfeeda" }}>
                    <span className="threat-label">🕒</span>
                    <strong style={{ marginLeft: 6, marginRight: 8 }}>Timestamp:</strong>
                    <span>{t.timestamp || 'N/A'}</span>
                  </div>

                  <div style={{ marginTop: "0.5rem", color: "#dbeee0" }}>
                    <em>Prevention:</em> {t.prevention || t.summary}
                  </div>

                  {t.prevention_steps && (userInfo?.role === "admin" || userInfo?.subscription === "premium") && (
                    <div style={{ marginTop: "0.25rem", color: "#cfeeda", fontSize: "0.9rem" }}>
                      <strong>Steps:</strong>
                      <ol style={{ margin: '0.4rem 0 0 1.2rem' }}>
                        {Array.isArray(t.prevention_steps) ? t.prevention_steps.map((s, i) => <li key={i}>{s}</li>) : <li>{t.prevention_steps}</li>}
                      </ol>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
      )}

      {/* Navigation tabs removed per user request */}

      {/* Overview removed by user request */}



      {/* Alerts Tab */}
      {activeTab === "alerts" && (
        <div className="tab-content alerts">
          <h2>Security Alerts</h2>
          {alerts.length === 0 ? (
            <p className="empty-state">✅ No alerts detected. Your websites are secure!</p>
          ) : (
            <div className="alerts-list">
              {alerts.map((alert) => (
                <div
                  key={alert.id}
                  className={`alert-card ${alert.threat_level} ${alert.is_read ? "read" : "unread"}`}
                >
                  <div className="alert-header">
                    <span className={`threat-badge ${alert.threat_level}`}>
                      {alert.threat_level.toUpperCase()}
                    </span>
                    <span className="alert-time">
                      {new Date(alert.created_at).toLocaleTimeString()}
                    </span>
                  </div>
                  <div className="alert-body">
                    <h3>{alert.threat_details}</h3>
                    <p>Website ID: #{alert.website_id}</p>
                  </div>
                  {!alert.is_read && (
                    <button
                      className="btn-mark-read"
                      onClick={() => handleMarkAlertRead(alert.id)}
                    >
                      Mark as Read
                    </button>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Blocked Threats Tab */}
      {activeTab === "blocked" && (
        <div className="tab-content blocked-threats">
          <h2>🛡️ Your Blocked IP Addresses</h2>
          {blockedThreatsLoading ? (
            <p className="loading-state">Loading blocked threats...</p>
          ) : blockedThreats.length === 0 ? (
            <p className="empty-state">No blocked IPs yet. You're protected!</p>
          ) : (
            <div className="blocked-threats-list">
              {blockedThreats.map((threat) => (
                <div 
                  key={threat.id} 
                  className={`blocked-threat-card ${!threat.is_active ? 'unblocked' : ''}`}
                  style={{
                    borderLeft: `4px solid ${
                      threat.risk_score >= 75 ? '#dc3545' : 
                      threat.risk_score >= 50 ? '#ffc107' : 
                      '#28a745'
                    }`
                  }}
                >
                  <div className="threat-header">
                    <code className="ip-badge">{threat.ip_address}</code>
                    <span className={`status-badge ${threat.is_active ? 'active' : 'inactive'}`}>
                      {threat.is_active ? '🟢 Active' : '⚫ Inactive'}
                    </span>
                  </div>
                  <div className="threat-details">
                    <div className="detail-row">
                      <span className="label">Type:</span>
                      <span className="value">{threat.threat_type}</span>
                    </div>
                    <div className="detail-row">
                      <span className="label">Risk Score:</span>
                      <span 
                        className="risk-score"
                        style={{
                          backgroundColor: threat.risk_score >= 75 ? '#dc3545' : 
                                         threat.risk_score >= 50 ? '#ffc107' : 
                                         '#28a745'
                        }}
                      >
                        {threat.risk_score}/100
                      </span>
                    </div>
                    <div className="detail-row">
                      <span className="label">Category:</span>
                      <span className="value">{threat.risk_category}</span>
                    </div>
                    <div className="detail-row">
                      <span className="label">Reason:</span>
                      <span className="value">{threat.reason}</span>
                    </div>
                    <div className="detail-row">
                      <span className="label">Blocked:</span>
                      <span className="value">{new Date(threat.blocked_at).toLocaleString()}</span>
                    </div>
                    {threat.summary && (
                      <div className="summary-section">
                        <p>{threat.summary}</p>
                      </div>
                    )}
                  </div>
                  {threat.is_active && (
                    <button 
                      className="btn-unblock"
                      onClick={() => handleUnblockIP(threat.id)}
                    >
                      🔓 Unblock IP
                    </button>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default UserDashboard;
