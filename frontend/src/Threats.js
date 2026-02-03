import React, { useEffect, useState } from "react";
import { API_URL } from "./config";

function Threats() {
  const [threats, setThreats] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const fetchThreats = async () => {
    try {
      const res = await fetch(`${API_URL}/threats`);
      const data = await res.json();
      setThreats(data);
      setLoading(false);
    } catch (err) {
      console.error("Error fetching threats:", err);
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchThreats();
    // Auto-refresh every 30 seconds
    const interval = setInterval(fetchThreats, 30000);
    return () => clearInterval(interval);
  }, []);

  const handleRefresh = async () => {
    setRefreshing(true);
    await fetchThreats();
    setRefreshing(false);
  };

  const getRiskLevel = (threat) => {
    const score = threat.score ?? 0;  // Use score field as primary
    const severity = (threat.severity || "").toLowerCase();
    
    // Risk levels: High (>=75, Red), Medium (50-74, Yellow), Low (<50, Green)
    if (severity === "high" || score >= 75) return { level: "High", color: "#dc3545" };
    if (severity === "medium" || (score >= 50 && score < 75)) return { level: "Medium", color: "#ffc107" };
    return { level: "Low", color: "#28a745" };
  };

  if (loading) return <p>Loading threats...</p>;

  return (
    <div style={{ padding: "1rem" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1rem" }}>
        <h2 style={{ margin: 0 }}>Threat Intelligence</h2>
        <button
          onClick={handleRefresh}
          disabled={refreshing}
          style={{
            padding: "0.5rem 0.9rem",
            backgroundColor: refreshing ? "#ccc" : "#28a745",
            color: "#fff",
            border: "none",
            borderRadius: "4px",
            cursor: refreshing ? "not-allowed" : "pointer",
            fontWeight: 700,
            opacity: refreshing ? 0.6 : 1,
          }}
        >
          {refreshing ? "Refreshing..." : "🔄 Refresh"}
        </button>
      </div>

      {!threats.length ? (
        <p>No threats found</p>
      ) : (
        <div style={{ display: "grid", gap: "1rem" }}>
          {threats.map((t, index) => {
            const risk = getRiskLevel(t);
            return (
              <div
                key={index}
                style={{
                  border: "1px solid #ddd",
                  borderRadius: "8px",
                  padding: "1rem",
                  position: "relative",
                  backgroundColor: "#fff",
                  boxShadow: "0 1px 3px rgba(0,0,0,0.1)",
                }}
              >
                <span
                  style={{
                    position: "absolute",
                    top: 12,
                    right: 12,
                    background: risk.color,
                    color: risk.level === "Medium" ? "#000" : "#fff",
                    padding: "4px 10px",
                    borderRadius: 999,
                    fontWeight: 700,
                    fontSize: "0.85rem",
                    textTransform: "uppercase",
                    boxShadow: "0 1px 3px rgba(0,0,0,0.15)",
                  }}
                >
                  {risk.level}
                </span>
                <h3 style={{ marginTop: 0, paddingRight: "80px" }}>
                  {t.indicator}
                </h3>
                <p><strong>Category:</strong> {t.category || "Other"}</p>
                <p><strong>Type:</strong> {t.type}</p>
                <p><strong>Summary:</strong> {t.summary}</p>
                <p>
                  <strong>Risk Score:</strong> {t.score ?? 0} / 100
                  <span style={{ marginLeft: "1rem", color: risk.color, fontWeight: "bold" }}>
                    ({risk.level} Risk)
                  </span>
                </p>
                {t.timestamp && (
                  <p style={{ fontSize: "0.85rem", color: "#666" }}>
                    <strong>Detected:</strong> {t.timestamp}
                  </p>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

export default Threats;
