import React, { useEffect, useState } from "react";
import ThreatCard from "./ThreatCard";
import { API_URL } from "../config";
import "../App.css";

function ThreatDashboard({ logout }) {
  const [threats, setThreats] = useState([]);
  const [users, setUsers] = useState([]);
  const [token, setToken] = useState(localStorage.getItem("token") || "");
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState(null);
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState("all");

  // Fetch threats from backend with auto-refresh every 30 seconds
  useEffect(() => {
    const fetchThreats = async () => {
      try {
        const res = await fetch(`${API_URL}/threats`);
        if (!res.ok) throw new Error(`Server error: ${res.status}`);
        const data = await res.json();
        setThreats(data);
      } catch (err) {
        setError("Unable to load threats. Check if backend is running.");
      } finally {
        setLoading(false);
        setRefreshing(false);
      }
    };
    fetchThreats();
    
    // Auto-refresh every 30 seconds for fresh data
    const interval = setInterval(fetchThreats, 30000);
    return () => clearInterval(interval);
  }, []);

  // Manual refresh handler
  const handleRefresh = async () => {
    setRefreshing(true);
    try {
      const res = await fetch(`${API_URL}/threats`);
      if (!res.ok) throw new Error(`Server error: ${res.status}`);
      const data = await res.json();
      setThreats(data);
      setError(null);
    } catch (err) {
      setError("Failed to refresh threats.");
    } finally {
      setRefreshing(false);
    }
  };

  // Fetch users from backend (for sending notifications)
  useEffect(() => {
    const fetchUsers = async () => {
      if (!token) return;
      try {
        const res = await fetch(`${API_URL}/users`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (!res.ok) throw new Error("Failed to fetch users");
        const data = await res.json();
        setUsers(data);
      } catch (err) {
        console.error("Error fetching users:", err);
      }
    };
    fetchUsers();
  }, [token]);

  const getRiskLevel = (score) => {
    if (score >= 75) return { level: "high", color: "#dc3545" };
    if (score >= 50) return { level: "medium", color: "#ffc107" };
    return { level: "low", color: "#28a745" };
  };

  const filteredThreats = threats.filter((t) => {
    const matchesSearch =
      t.indicator?.toLowerCase().includes(search.toLowerCase()) ||
      t.title?.toLowerCase().includes(search.toLowerCase());
    const risk = getRiskLevel(t.score).level;
    return (filter === "all" || filter === risk) && matchesSearch;
  });

  if (loading) return <h2 className="center">Loading threats...</h2>;
  if (error) return <h2 className="center error">{error}</h2>;

  return (
    <div className="container">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1rem" }}>
        <h1>Threat Intelligence Dashboard</h1>
        <div style={{ display: "flex", gap: "10px", alignItems: "center" }}>
          <button
            onClick={handleRefresh}
            disabled={refreshing}
            style={{
              padding: "0.5rem 1rem",
              backgroundColor: refreshing ? "#ccc" : "#28a745",
              color: "white",
              border: "none",
              borderRadius: "4px",
              cursor: refreshing ? "not-allowed" : "pointer",
              fontWeight: "600",
            }}
          >
            {refreshing ? "Refreshing..." : "🔄 Refresh"}
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
      </div>

      <div className="controls" style={{ marginBottom: "1rem" }}>
        <input
          type="text"
          placeholder="Search threats..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          style={{ padding: "0.5rem", width: "60%", marginRight: "1rem" }}
        />
        <select
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          style={{ padding: "0.5rem" }}
        >
          <option value="all">All</option>
          <option value="low">Low Risk</option>
          <option value="medium">Medium Risk</option>
          <option value="high">High Risk</option>
        </select>
      </div>

      <div className="grid">
        {filteredThreats.length === 0 ? (
          <p>No matching threats found.</p>
        ) : (
          filteredThreats.map((t, index) => (
            <ThreatCard key={index} threat={t} users={users} token={token} />
          ))
        )}
      </div>
    </div>
  );
}

export default ThreatDashboard;
