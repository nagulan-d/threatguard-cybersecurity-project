import React, { useEffect, useState } from "react";
import ThreatCard from "./ThreatCard";
import { API_ORIGIN, API_URL } from "../config";
import "../App.css";

function AdminDashboard({ logout }) {
  const [users, setUsers] = useState([]);
  const [websites, setWebsites] = useState([]);
  const [threats, setThreats] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [threatsLoading, setThreatsLoading] = useState(true);
  const [error, setError] = useState(null);
  const [upgrading, setUpgrading] = useState(null);
  const [notifications, setNotifications] = useState([]);
  const [showRequests, setShowRequests] = useState(false);
  const [selectedCategory, setSelectedCategory] = useState('All');
  const [me, setMe] = useState(null);
  const [userBlocks, setUserBlocks] = useState([]);
  const [showBlocks, setShowBlocks] = useState(false);

  const CATEGORIES = [
    'All',
    'Phishing',
    'Ransomware',
    'Malware',
    'DDoS Attacks',
    'Vulnerability Exploits',
    'Current Threats'
  ];

  const isRecent = (t) => {
    try {
      if (t.alert) return true;
      const ts = t.timestamp || t.created_at || t.modified || t.time || null;
      if (!ts) return false;
      const d = new Date(ts);
      if (isNaN(d)) return false;
      const diffDays = (Date.now() - d.getTime()) / (1000 * 60 * 60 * 24);
      return diffDays <= 30;
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
    if (!category || category === 'All') return true;
    if (category === 'Current Threats') return isRecent(t);
    return categorizeThreat(t) === category;
  };

  // Get token at component level
  const getToken = () => {
    const token = localStorage.getItem("token");
    console.log("🔐 Token retrieved:", token ? `${token.substring(0, 20)}...` : "NOT FOUND");
    return token;
  };

  // Fetch latest admin notifications (upgrade requests, etc.)
  const fetchNotifications = async () => {
    try {
      const currentToken = getToken();
      const rawToken = normalizeToken(currentToken);
      if (!rawToken) return;
      const res = await fetch(`${API_URL}/admin-notifications`, {
        method: "GET",
        headers: { "Content-Type": "application/json", "Authorization": `Bearer ${rawToken}` },
      });
      if (res.ok) {
        const data = await res.json();
        setNotifications(data);
      } else {
        console.warn("Failed to fetch notifications", res.status);
      }
    } catch (e) {
      console.error("Error fetching notifications:", e);
    }
  };

  // Fetch user blocks for admin visibility
  const fetchUserBlocks = async () => {
    try {
      const currentToken = getToken();
      const rawToken = normalizeToken(currentToken);
      if (!rawToken) return;
      const res = await fetch(`${API_URL}/admin/blocked-threats?is_active=true`, {
        method: "GET",
        headers: { "Content-Type": "application/json", "Authorization": `Bearer ${rawToken}` },
      });
      if (res.ok) {
        const data = await res.json();
        setUserBlocks(data.blocked_threats || []);
      } else {
        console.warn("Failed to fetch user blocks", res.status);
      }
    } catch (e) {
      console.error("Error fetching user blocks:", e);
    }
  };

  // Normalize token: strip leading 'Bearer ' if present and remove surrounding quotes
  const normalizeToken = (t) => {
    if (!t) return "";
    let token = t;
    if (token.startsWith("Bearer ")) token = token.slice(7);
    // remove surrounding double quotes if accidentally stored
    token = token.replace(/^"|"$/g, "");
    return token;
  };

  // (Test token removed) token normalization helper remains in use by fetches

  const token = getToken();

  // Fetch core admin data in parallel
  useEffect(() => {
    const fetchAdminData = async () => {
      const currentToken = getToken();
      const rawToken = normalizeToken(currentToken);

      if (!rawToken) {
        console.error("❌ No token found in localStorage");
        setError("No authentication token found. Please login again.");
        setLoading(false);
        return;
      }

      try {
        console.log("📡 Fetching admin data with token...");
        
        // Fetch users and websites in parallel
        const [usersRes, websitesRes, alertsRes] = await Promise.all([
          fetch(`${API_URL}/users`, {
            method: "GET",
            headers: {
              "Content-Type": "application/json",
              "Authorization": `Bearer ${rawToken}`,
            },
          }),
          fetch(`${API_URL}/all-websites`, {
            method: "GET",
            headers: {
              "Content-Type": "application/json",
              "Authorization": `Bearer ${rawToken}`,
            },
          }),
          fetch(`${API_URL}/admin-alerts`, {
            method: "GET",
            headers: {
              "Content-Type": "application/json",
              "Authorization": `Bearer ${rawToken}`,
            },
          }),
          fetch(`${API_URL}/admin-notifications`, {
            method: "GET",
            headers: {
              "Content-Type": "application/json",
              "Authorization": `Bearer ${rawToken}`,
            },
          }),
        ]);

        console.log(`📊 API Responses: users=${usersRes.status}, websites=${websitesRes.status}, alerts=${alertsRes.status}`);

        // Check for errors
        if (!usersRes.ok) {
          if (usersRes.status === 401) {
            throw new Error("Unauthorized - Token may have expired. Please login again.");
          } else if (usersRes.status === 403) {
            throw new Error("Forbidden - Admin access required.");
          }
          throw new Error(`Users fetch error: ${usersRes.status}`);
        }

        if (!websitesRes.ok) {
          if (websitesRes.status === 401) {
            throw new Error("Unauthorized - Token may have expired. Please login again.");
          } else if (websitesRes.status === 403) {
            throw new Error("Forbidden - Admin access required.");
          }
          throw new Error(`Websites fetch error: ${websitesRes.status}`);
        }

        // Parse responses
        const usersData = await usersRes.json();
        const websitesData = await websitesRes.json();
        const alertsData = alertsRes.ok ? await alertsRes.json() : [];
        // Fetch current user profile for convenience (email target for test email)
        try {
          const meRes = await fetch(`${API_URL}/me`, {
            method: "GET",
            headers: { "Content-Type": "application/json", "Authorization": `Bearer ${rawToken}` },
          });
          if (meRes.ok) {
            const meData = await meRes.json();
            setMe(meData);
          }
        } catch (e) {
          console.warn("Failed to fetch /api/me:", e);
        }
        // admin-notifications is the 4th result in our parallel fetch (alertsRes was 3rd)
        let notificationsData = [];
        try {
          const notesRes = await fetch(`${API_URL}/admin-notifications`, {
            method: "GET",
            headers: { "Content-Type": "application/json", "Authorization": `Bearer ${rawToken}` },
          });
          notificationsData = notesRes.ok ? await notesRes.json() : [];
        } catch (e) {
          console.warn("Failed to fetch admin notifications separately:", e);
        }

        console.log("✅ Data loaded successfully");

        // Set admin data
        setUsers(usersData);
        setWebsites(websitesData);
        setAlerts(alertsData);
        setNotifications(notificationsData);
      } catch (err) {
        console.error("❌ Error fetching admin data:", err);
        const msg = err.message || "Unable to load admin data. Check backend.";
        setError(msg);
        // If unauthorized, clear auth and redirect to login by calling logout()
        if (msg.toLowerCase().includes("unauthorized") || msg.toLowerCase().includes("token")) {
          try {
            logout();
          } catch (e) {
            console.warn("Failed to call logout():", e);
          }
        }
      } finally {
        setLoading(false);
      }
    };

    fetchAdminData();
    
    // Auto-refresh admin data every 30 seconds for fresh threat/user/website updates
    const interval = setInterval(fetchAdminData, 30000);
    return () => clearInterval(interval);
  }, []);


  // Fetch live threats (refresh=true) on every request; bypass cache entirely.
  const fetchThreats = async (opts = {}) => {
    setThreatsLoading(true);
    const currentToken = getToken();
    const rawToken = normalizeToken(currentToken);
    if (!rawToken) {
      setThreats([]);
      setThreatsLoading(false);
      return;
    }

    try {
      // Simple fetch without refresh parameter
      const limit = selectedCategory && selectedCategory !== 'All' ? 5 : 15;
      const cat = encodeURIComponent(selectedCategory || 'All');
      let url = (selectedCategory && selectedCategory !== 'All')
        ? `${API_URL}/threats?limit=${limit}&category=${cat}`
        : `${API_URL}/threats?limit=${limit}`;

      const res = await fetch(url, {
        method: "GET",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${rawToken}`,
        },
      });

      if (res.ok) {
        const data = await res.json();
        setThreats(Array.isArray(data) ? data : []);
      } else if (res.status === 504) {
        console.error("Gateway timeout - OTX API slow or unavailable");
        setThreats([]);
      } else {
        setThreats([]);
      }
    } catch (err) {
      console.error("Error fetching threats:", err);
      setThreats([]);
    } finally {
      setThreatsLoading(false);
    }
  };

  // AUTO-BLOCK HIGH-RISK THREATS
  const autoBlockThreats = async () => {
    try {
      const currentToken = getToken();
      const rawToken = normalizeToken(currentToken);
      if (!rawToken) return;

      console.log("🛡️ Starting automatic threat blocking...");
      
      const res = await fetch(`${API_URL}/admin/auto-block-threats`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${rawToken}`,
        },
      });

      if (res.ok) {
        const data = await res.json();
        console.log("✅ Auto-block complete:", data.summary);
        
        // Refresh blocked threats list
        fetchUserBlocks();
        
        // Show notification to admin
        if (data.auto_blocked && data.auto_blocked.length > 0) {
          alert(`🛡️ Auto-Blocked ${data.auto_blocked.length} high-risk threats!\n\nSummary:\n- Blocked: ${data.summary.successfully_auto_blocked}\n- Already blocked: ${data.summary.already_blocked}\n- Invalid IPs: ${data.summary.invalid_ips}`);
        }
      } else {
        console.error("Auto-block failed:", res.status);
      }
    } catch (err) {
      console.error("Error during auto-block:", err);
    }
  };

  // DEACTIVATE SINGLE BLOCKED IP
  const handleDeactivateBlockedIP = async (threatId, ipAddress) => {
    if (!window.confirm(`Deactivate blocking for IP ${ipAddress}?`)) {
      return;
    }

    try {
      const currentToken = getToken();
      const rawToken = normalizeToken(currentToken);
      if (!rawToken) return;

      const res = await fetch(`${API_URL}/unblock-threat/${threatId}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${rawToken}`,
        },
      });

      if (res.ok) {
        console.log(`✅ Deactivated block for IP ${ipAddress}`);
        // Refresh blocked threats list
        fetchUserBlocks();
        alert(`✅ Deactivated block for ${ipAddress}`);
      } else {
        const data = await res.json();
        alert(`❌ Failed to deactivate: ${data.error || 'Unknown error'}`);
      }
    } catch (err) {
      console.error("Error deactivating blocked IP:", err);
      alert("❌ Failed to deactivate blocked IP");
    }
  };

  // DEACTIVATE ALL AUTO-BLOCKED IPS
  const handleDeactivateAllBlockedIPs = async () => {
    const autoBlockedCount = userBlocks.filter(b => b.blocked_by === 'admin' && b.is_active).length;
    
    if (autoBlockedCount === 0) {
      alert("No active auto-blocked IPs to deactivate.");
      return;
    }

    if (!window.confirm(`Deactivate all ${autoBlockedCount} auto-blocked IPs?`)) {
      return;
    }

    try {
      const currentToken = getToken();
      const rawToken = normalizeToken(currentToken);
      if (!rawToken) return;

      // Deactivate each active auto-blocked IP
      const activeAutoBlocked = userBlocks.filter(b => b.blocked_by === 'admin' && b.is_active);
      let successCount = 0;
      let failCount = 0;

      for (const block of activeAutoBlocked) {
        try {
          const res = await fetch(`${API_URL}/unblock-threat/${block.id}`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "Authorization": `Bearer ${rawToken}`,
            },
          });

          if (res.ok) {
            successCount++;
          } else {
            failCount++;
          }
        } catch (err) {
          failCount++;
        }
      }

      // Refresh blocked threats list
      await fetchUserBlocks();

      alert(`✅ Deactivation complete!\n- Successfully deactivated: ${successCount}\n- Failed: ${failCount}`);
    } catch (err) {
      console.error("Error deactivating all blocked IPs:", err);
      alert("❌ Failed to deactivate all blocked IPs");
    }
  };

  // Deactivate all user blocks at once
  const handleDeactivateAllUserBlocks = async () => {
    const activeUserBlocks = userBlocks.filter(b => b.is_active);
    
    if (activeUserBlocks.length === 0) {
      alert("No active user blocks to deactivate.");
      return;
    }

    try {
      const currentToken = getToken();
      const rawToken = normalizeToken(currentToken);
      if (!rawToken) return;

      let successCount = 0;
      let failCount = 0;

      // Deactivate each active user block
      for (const block of activeUserBlocks) {
        try {
          const res = await fetch(`${API_URL}/unblock-threat/${block.id}`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "Authorization": `Bearer ${rawToken}`,
            },
          });

          if (res.ok) {
            successCount++;
          } else {
            failCount++;
          }
        } catch (err) {
          failCount++;
        }
      }

      // Refresh user blocks list
      await fetchUserBlocks();

      alert(`✅ Deactivation complete!\n- Successfully deactivated: ${successCount}\n- Failed: ${failCount}`);
    } catch (err) {
      console.error("Error deactivating all user blocks:", err);
      alert("❌ Failed to deactivate all user blocks");
    }
  };

  useEffect(() => {
    fetchThreats();
  }, [selectedCategory]);

  // Auto-block threats when admin dashboard loads
  useEffect(() => {
    const timer = setTimeout(() => {
      console.log("⏰ Initiating auto-block on admin dashboard load...");
      autoBlockThreats();
    }, 1000); // Wait 1 second for threats to load

    return () => clearTimeout(timer);
  }, []);


  // Upgrade user to premium
  const handleUpgradeUser = async (userId) => {
    setUpgrading(userId);
    try {
      const currentToken = getToken();
      const rawToken = normalizeToken(currentToken);
      const res = await fetch(`${API_URL}/upgrade-user`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${rawToken}`,
        },
        body: JSON.stringify({ user_id: userId }),
      });

      if (res.ok) {
        // Update local user state
        setUsers(users.map(u => 
          u.id === userId ? { ...u, subscription: "premium" } : u
        ));
        // Remove any notifications related to this user (request fulfilled)
        setNotifications((prev) => prev.filter(n => n.user_id !== userId));
        alert("✅ User upgraded to Premium!");
      } else {
        const errorData = await res.json();
        alert(`❌ Upgrade failed: ${errorData.error}`);
      }
    } catch (err) {
      console.error("Error upgrading user:", err);
      alert("❌ Failed to upgrade user");
    } finally {
      setUpgrading(null);
    }
  };

  const handleMarkNotificationRead = async (noteId) => {
    try {
      const currentToken = getToken();
      const rawToken = normalizeToken(currentToken);
      const res = await fetch(`${API_URL}/notifications/${noteId}/read`, {
        method: "PUT",
        headers: { "Content-Type": "application/json", "Authorization": `Bearer ${rawToken}` },
      });
      if (res.ok) {
        setNotifications((prev) => prev.filter(n => n.id !== noteId));
      } else {
        const err = await res.json();
        alert(`Failed: ${err.error || 'Unable to mark read'}`);
      }
    } catch (err) {
      console.error("Error marking notification read:", err);
      alert("Failed to mark notification read");
    }
  };

  // Downgrade user from premium to free
  const handleDowngradeUser = async (userId) => {
    if (!window.confirm("Are you sure you want to downgrade this user to Free plan?")) {
      return;
    }
    setUpgrading(userId);
    try {
      const currentToken = getToken();
      const rawToken = normalizeToken(currentToken);
      const res = await fetch(`${API_URL}/downgrade-user`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${rawToken}`,
        },
        body: JSON.stringify({ user_id: userId }),
      });

      if (res.ok) {
        // Update local user state
        setUsers(users.map(u => 
          u.id === userId ? { ...u, subscription: "free" } : u
        ));
        alert("✅ User downgraded to Free plan!");
      } else {
        const errorData = await res.json();
        alert(`❌ Downgrade failed: ${errorData.error}`);
      }
    } catch (err) {
      console.error("Error downgrading user:", err);
      alert("❌ Failed to downgrade user");
    } finally {
      setUpgrading(null);
    }
  };

  // Delete user account
  const handleDeleteUser = async (userId, username) => {
    if (!window.confirm(`Are you sure you want to DELETE the account "${username}" and all associated data? This action cannot be undone.`)) {
      return;
    }
    setUpgrading(userId);
    try {
      const currentToken = getToken();
      const rawToken = normalizeToken(currentToken);
      const res = await fetch(`${API_URL}/delete-user`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${rawToken}`,
        },
        body: JSON.stringify({ user_id: userId }),
      });

      if (res.ok) {
        // Remove user from local state
        setUsers(users.filter(u => u.id !== userId));
        alert("✅ User account deleted successfully!");
      } else {
        const errorData = await res.json();
        alert(`❌ Delete failed: ${errorData.error}`);
      }
    } catch (err) {
      console.error("Error deleting user:", err);
      alert("❌ Failed to delete user account");
    } finally {
      setUpgrading(null);
    }
  };

  if (loading) return <h2 className="center">Loading admin dashboard...</h2>;
  if (error) return <h2 className="center error">{error}</h2>;

  return (
    <div className="container admin-dashboard">
      <h1>Admin Dashboard</h1>
      <div style={{ float: "right", marginBottom: "1rem", display: 'flex', gap: '8px', alignItems: 'center' }}>
        {/* Requests button toggles visibility of admin notifications and refreshes them when opened */}
        <button
          onClick={async () => {
            const willShow = !showRequests;
            setShowRequests(willShow);
            if (willShow) await fetchNotifications();
          }}
          title="Show user upgrade requests"
          style={{
            padding: '0.5rem 0.9rem',
            backgroundColor: '#06b06b',
            color: '#fff',
            border: 'none',
            borderRadius: '4px',
            cursor: 'pointer',
            fontWeight: 700,
          }}
        >
          Requests {notifications && notifications.filter(n => !n.is_read).length > 0 && (
            <span style={{ marginLeft: 8, background: '#ff4757', color: '#fff', borderRadius: 12, padding: '2px 8px', fontSize: '0.8rem' }}>{notifications.filter(n => !n.is_read).length}</span>
          )}
        </button>
        {/* User Blocks button - shows which users blocked which IPs */}
        <button
          onClick={async () => {
            const willShow = !showBlocks;
            setShowBlocks(willShow);
            if (willShow) await fetchUserBlocks();
          }}
          title="View user IP blocks"
          style={{
            padding: '0.5rem 0.9rem',
            backgroundColor: '#e74c3c',
            color: '#fff',
            border: 'none',
            borderRadius: '4px',
            cursor: 'pointer',
            fontWeight: 700,
          }}
        >
          🔒 User Blocks {userBlocks.length > 0 && (
            <span style={{ marginLeft: 8, background: '#c0392b', color: '#fff', borderRadius: 12, padding: '2px 8px', fontSize: '0.8rem' }}>{userBlocks.length}</span>
          )}
        </button>
        <button
          onClick={logout}
          style={{
            padding: "0.5rem 1rem",
            backgroundColor: "#d9534f",
            color: "white",
            border: "none",
            borderRadius: "4px",
            cursor: "pointer",
          }}
        >
          Logout
        </button>
      </div>

      <section>
        <h2>Registered Users</h2>
        {users.length === 0 ? (
          <p>No users found.</p>
        ) : (
          <table className="user-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Username</th>
                <th>Email</th>
                <th>Subscription</th>
                <th>Role</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.id}>
                  <td>{u.id}</td>
                  <td>{u.username}</td>
                  <td>{u.email}</td>
                  <td><span style={{ padding: "0.3rem 0.6rem", borderRadius: "4px", backgroundColor: u.subscription === "premium" ? "#28a745" : "#6c757d", color: "white", fontSize: "0.85rem" }}>{u.subscription}</span></td>
                  <td>{u.role}</td>
                  <td>
                    {u.role === "admin" ? (
                      <span style={{ color: "#6c757d", fontWeight: "600", fontSize: "0.85rem" }}>-</span>
                    ) : (
                      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                        {u.subscription === "free" ? (
                          <button
                            onClick={() => handleUpgradeUser(u.id)}
                            disabled={upgrading === u.id}
                            style={{
                              padding: "0.4rem 0.8rem",
                              backgroundColor: "#28a745",
                              color: "white",
                              border: "none",
                              borderRadius: "4px",
                              cursor: upgrading === u.id ? "not-allowed" : "pointer",
                              fontSize: "0.85rem",
                              fontWeight: "600",
                              opacity: upgrading === u.id ? 0.6 : 1,
                            }}
                          >
                            {upgrading === u.id ? "Upgrading..." : "Upgrade"}
                          </button>
                        ) : (
                          <button
                            onClick={() => handleDowngradeUser(u.id)}
                            disabled={upgrading === u.id}
                            style={{
                              padding: "0.4rem 0.8rem",
                              backgroundColor: "#dc3545",
                              color: "white",
                              border: "none",
                              borderRadius: "4px",
                              cursor: upgrading === u.id ? "not-allowed" : "pointer",
                              fontSize: "0.85rem",
                              fontWeight: "600",
                              opacity: upgrading === u.id ? 0.6 : 1,
                            }}
                          >
                            {upgrading === u.id ? "Downgrading..." : "Downgrade"}
                          </button>
                        )}
                        <button
                          onClick={() => handleDeleteUser(u.id, u.username)}
                          disabled={upgrading === u.id}
                          style={{
                            padding: "0.4rem 0.8rem",
                            backgroundColor: "#c0392b",
                            color: "white",
                            border: "none",
                            borderRadius: "4px",
                            cursor: upgrading === u.id ? "not-allowed" : "pointer",
                            fontSize: "0.85rem",
                            fontWeight: "600",
                            opacity: upgrading === u.id ? 0.6 : 1,
                          }}
                          title="Delete this user account and all associated data"
                        >
                          {upgrading === u.id ? "Deleting..." : "🗑️ Remove"}
                        </button>
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section style={{ marginTop: "2rem" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1rem" }}>
          <h2 style={{ margin: 0 }}>Latest Threats</h2>
          <button
            onClick={async () => {
              setThreatsLoading(true);
              await fetchThreats();
              setThreatsLoading(false);
            }}
            disabled={threatsLoading}
            style={{
              padding: "0.5rem 0.9rem",
              backgroundColor: threatsLoading ? "#ccc" : "#28a745",
              color: "#fff",
              border: "none",
              borderRadius: "4px",
              cursor: threatsLoading ? "not-allowed" : "pointer",
              fontWeight: 700,
              opacity: threatsLoading ? 0.6 : 1,
            }}
          >
            {threatsLoading ? "Refreshing..." : "🔄 Refresh Threats"}
          </button>
        </div>

        {/* Filter bar (always visible) - match the requested markup/styles */}
        <div className="filter-bar">
          <label htmlFor="category-select" style={{ marginRight: 8, color: 'rgb(207, 238, 218)' }}>Category:</label>
          <select
            id="category-select"
            value={selectedCategory}
            onChange={(e) => setSelectedCategory(e.target.value)}
            style={{ padding: '6px 10px', borderRadius: 6, background: 'rgb(11, 42, 13)', color: 'rgb(207, 238, 218)', border: '1px solid rgb(20, 66, 26)' }}
          >
            {CATEGORIES.map((c) => (
              <option key={c} value={c}>{c}</option>
            ))}
          </select>
        </div>

        {threatsLoading ? (
          <p>Loading threats...</p>
        ) : threats.length === 0 ? (
          <div style={{ padding: '0.75rem 0' }}>
            <p style={{ color: '#666' }}>No threats found for the selected category. Try a different category or select "All".</p>
          </div>
        ) : (
          <div>
            <div className="grid">
              {threats.filter(t => matchesCategory(t, selectedCategory)).map((t, index) => (
                <ThreatCard key={index} threat={t} users={users} token={token} />
              ))}
            </div>
          </div>
        )}
        
      </section>

      {/* AUTO-BLOCKED THREATS SECTION */}
      <section style={{ marginTop: "2rem", padding: "1.5rem", backgroundColor: "#1a472a", borderRadius: "8px", border: "2px solid #28a745" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1rem" }}>
          <h2 style={{ margin: 0, color: "#28a745" }}>🛡️ Auto-Blocked High-Risk Threats</h2>
          <div style={{ display: "flex", gap: "0.5rem" }}>
            <button
              onClick={async () => {
                console.log("🛡️ Manually triggering auto-block...");
                await autoBlockThreats();
              }}
              style={{
                padding: "0.5rem 1rem",
                backgroundColor: "#28a745",
                color: "white",
                border: "none",
                borderRadius: "4px",
                cursor: "pointer",
                fontWeight: 700,
              }}
            >
              🔄 Scan & Block Now
            </button>
            {userBlocks.filter(b => b.blocked_by === 'admin' && b.is_active).length > 0 && (
              <button
                onClick={handleDeactivateAllBlockedIPs}
                style={{
                  padding: "0.5rem 1rem",
                  backgroundColor: "#ffc107",
                  color: "#000",
                  border: "none",
                  borderRadius: "4px",
                  cursor: "pointer",
                  fontWeight: 700,
                }}
                title="Deactivate all auto-blocked IPs"
              >
                ⚠️ Deactivate All
              </button>
            )}
          </div>
        </div>
        <p style={{ fontSize: '0.9rem', color: '#ccc', marginBottom: '1rem' }}>
          Automatically blocks all threats with risk score ≥ 75 from the threat feed.
        </p>
        {userBlocks.length === 0 ? (
          <p style={{ color: '#999' }}>No auto-blocked threats yet. Run scan to identify high-risk IPs.</p>
        ) : (
          <div>
            <p style={{ fontSize: '0.9rem', color: '#ccc', marginBottom: '1rem' }}>
              <strong>Total Auto-Blocked:</strong> {userBlocks.filter(b => b.blocked_by === 'admin').length} IPs | 
              <strong style={{ marginLeft: '1rem' }}>Active:</strong> {userBlocks.filter(b => b.blocked_by === 'admin' && b.is_active).length}
            </p>
            <table className="user-table" style={{ backgroundColor: "#0d2818" }}>
              <thead>
                <tr style={{ backgroundColor: "#1a472a" }}>
                  <th style={{ color: "#28a745" }}>IP Address</th>
                  <th style={{ color: "#28a745" }}>Threat Type</th>
                  <th style={{ color: "#28a745" }}>Risk Score</th>
                  <th style={{ color: "#28a745" }}>Category</th>
                  <th style={{ color: "#28a745" }}>Reason</th>
                  <th style={{ color: "#28a745" }}>Blocked At</th>
                  <th style={{ color: "#28a745" }}>Status</th>
                  <th style={{ color: "#28a745" }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {userBlocks
                  .filter(b => b.blocked_by === 'admin')
                  .sort((a, b) => new Date(b.blocked_at) - new Date(a.blocked_at))
                  .map((block, idx) => (
                    <tr key={block.id} style={{ backgroundColor: idx % 2 === 0 ? "#0d2818" : "#132419" }}>
                      <td style={{ fontFamily: 'monospace', color: '#ffcc00' }}>{block.ip_address}</td>
                      <td>{block.threat_type}</td>
                      <td>
                        <span style={{
                          padding: "0.3rem 0.6rem",
                          borderRadius: "4px",
                          backgroundColor: block.risk_score >= 75 ? "#dc3545" : block.risk_score >= 50 ? "#ffc107" : "#28a745",
                          color: block.risk_score >= 75 ? "white" : "#000",
                          fontWeight: "600",
                          fontSize: "0.9rem"
                        }}>
                          {block.risk_score.toFixed(1)}
                        </span>
                      </td>
                      <td>{block.risk_category}</td>
                      <td style={{ fontSize: '0.85rem', maxWidth: '300px' }}>
                        <span title={block.reason}>{block.reason.substring(0, 40)}...</span>
                      </td>
                      <td style={{ fontSize: '0.85rem' }}>{new Date(block.blocked_at).toLocaleString()}</td>
                      <td>
                        <span style={{
                          padding: "0.3rem 0.6rem",
                          borderRadius: "4px",
                          backgroundColor: block.is_active ? "#28a745" : "#6c757d",
                          color: "white",
                          fontWeight: "600",
                          fontSize: "0.85rem"
                        }}>
                          {block.is_active ? "🟢 Active" : "⚫ Inactive"}
                        </span>
                      </td>
                      <td>
                        {block.is_active && (
                          <button
                            onClick={() => handleDeactivateBlockedIP(block.id, block.ip_address)}
                            style={{
                              padding: "0.3rem 0.6rem",
                              backgroundColor: "#ffc107",
                              color: "#000",
                              border: "none",
                              borderRadius: "3px",
                              cursor: "pointer",
                              fontSize: "0.8rem",
                              fontWeight: "600"
                            }}
                            title={`Deactivate block for ${block.ip_address}`}
                          >
                            ⚠️ Deactivate
                          </button>
                        )}
                        {!block.is_active && (
                          <span style={{ fontSize: '0.8rem', color: '#999' }}>Deactivated</span>
                        )}
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {showRequests && (
        <section style={{ marginTop: "2rem" }}>
          <h2>Admin Notifications (Upgrade Requests)</h2>
          {notifications.length === 0 ? (
            <p>No upgrade requests at the moment.</p>
          ) : (
            <table className="user-table">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Requester</th>
                  <th>Email</th>
                  <th>Subject</th>
                  <th>Body</th>
                  <th>Created At</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {notifications.map((n) => (
                  <tr key={n.id}>
                    <td>{n.id}</td>
                    <td>{n.username || `#${n.user_id}`}</td>
                    <td>{n.email || 'N/A'}</td>
                    <td>{n.subject}</td>
                    <td style={{ maxWidth: 400, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{n.body}</td>
                    <td>{new Date(n.created_at).toLocaleString()}</td>
                    <td>
                      {n.user_id ? (
                        <>
                          <button onClick={() => handleUpgradeUser(n.user_id)} style={{ marginRight: 8, padding: '0.4rem 0.6rem' }}>Upgrade</button>
                          <button onClick={() => handleMarkNotificationRead(n.id)} style={{ padding: '0.35rem 0.6rem' }}>Mark Read</button>
                        </>
                      ) : (
                        <button onClick={() => handleMarkNotificationRead(n.id)}>Mark Read</button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>
      )}

      {showBlocks && (
        <section style={{ marginTop: "2rem" }}>
          <h2>🔒 User IP Blocks (Admin View)</h2>
          <p style={{ fontSize: '0.9rem', color: '#666', marginBottom: '1rem' }}>
            Track which users have blocked which IP addresses via email notifications
          </p>
          {userBlocks.length === 0 ? (
            <p>No user blocks recorded yet.</p>
          ) : (
            <>
              <div style={{ marginBottom: '1rem', display: 'flex', gap: '10px', alignItems: 'center' }}>
                <span style={{ fontSize: '0.9rem', color: '#666' }}>
                  Total Blocks: {userBlocks.length} | Active: {userBlocks.filter(b => b.is_active).length}
                </span>
                {userBlocks.some(b => b.is_active) && (
                  <button 
                    onClick={() => {
                      const activeCount = userBlocks.filter(b => b.is_active).length;
                      if (window.confirm(`Deactivate all ${activeCount} active user blocks?`)) {
                        handleDeactivateAllUserBlocks();
                      }
                    }}
                    style={{
                      padding: '8px 16px',
                      background: '#ffb347',
                      border: 'none',
                      borderRadius: 4,
                      cursor: 'pointer',
                      color: '#000',
                      fontWeight: 600,
                      fontSize: '0.9rem'
                    }}
                  >
                    ⚠️ Deactivate All
                  </button>
                )}
              </div>
              <table className="user-table">
                <thead>
                  <tr>
                    <th>Block ID</th>
                    <th>User</th>
                    <th>IP Address</th>
                    <th>Threat Type</th>
                    <th>Risk Score</th>
                    <th>Blocked By</th>
                    <th>Blocked At</th>
                    <th>Status</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {userBlocks.map((block) => (
                    <tr key={block.id}>
                      <td>{block.id}</td>
                      <td><strong>{block.username}</strong></td>
                      <td><code style={{ background: '#f5f5f5', padding: '2px 6px', borderRadius: 3 }}>{block.ip_address}</code></td>
                      <td>{block.threat_type}</td>
                      <td>
                        <span style={{
                          padding: '4px 8px',
                          borderRadius: 4,
                          background: block.risk_score >= 75 ? '#dc3545' : block.risk_score >= 50 ? '#ffc107' : '#28a745',
                          color: '#fff',
                          fontSize: '0.85rem',
                          fontWeight: 600
                        }}>
                          {block.risk_score}
                        </span>
                      </td>
                      <td>{block.blocked_by === 'user' ? '👤 User' : '👨‍💼 Admin'} ({block.blocked_by_username})</td>
                      <td>{new Date(block.blocked_at).toLocaleString()}</td>
                      <td>
                        <span style={{
                          padding: '4px 10px',
                          borderRadius: 4,
                          background: block.is_active ? '#28a745' : '#6c757d',
                          color: '#fff',
                          fontSize: '0.8rem'
                        }}>
                          {block.is_active ? '🟢 Active' : '⚫ Inactive'}
                        </span>
                      </td>
                      <td>
                        {block.is_active ? (
                          <button
                            onClick={() => {
                              if (window.confirm(`Deactivate block for ${block.ip_address}?`)) {
                                handleDeactivateBlockedIP(block.id, block.ip_address);
                              }
                            }}
                            style={{
                              padding: '6px 12px',
                              background: '#ffb347',
                              border: 'none',
                              borderRadius: 4,
                              cursor: 'pointer',
                              color: '#000',
                              fontWeight: 600,
                              fontSize: '0.85rem'
                            }}
                          >
                            ⚠️ Deactivate
                          </button>
                        ) : (
                          <span style={{ color: '#999', fontSize: '0.85rem' }}>Deactivated</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          )}
        </section>
      )}
      

      {alerts.length > 0 && (
        <section style={{ marginTop: "2rem" }}>
          <h2>Website Alerts</h2>
          <table className="user-table">
            <thead>
              <tr>
                <th>Alert ID</th>
                <th>Website ID</th>
                <th>Threat Level</th>
                <th>Details</th>
                <th>Created At</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map((alert) => (
                <tr key={alert.id}>
                  <td>{alert.id}</td>
                  <td>{alert.website_id}</td>
                  <td>
                    <span style={{
                      padding: "0.3rem 0.6rem",
                      borderRadius: "4px",
                      backgroundColor: alert.threat_level === "high" ? "#dc3545" : alert.threat_level === "medium" ? "#ffc107" : "#28a745",
                      color: alert.threat_level === "medium" ? "#000" : "#fff",
                      fontSize: "0.85rem"
                    }}>
                      {alert.threat_level}
                    </span>
                  </td>
                  <td>{alert.threat_details || "N/A"}</td>
                  <td>{new Date(alert.created_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}
    </div>
  );
}

export default AdminDashboard;