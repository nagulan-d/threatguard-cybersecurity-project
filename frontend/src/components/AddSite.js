import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import "../styles/Login.css"; // reuse button styles
import logo from '../assets/logo.jpg';

function AddSite() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();
  const token = localStorage.getItem("token");
  const API_URL = "http://127.0.0.1:5000/api";

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!url.trim()) return;
    setLoading(true);

    // Check subscription limit by fetching /me and /websites
    try {
      const meRes = await fetch(`${API_URL}/me`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!meRes.ok) throw new Error("Failed to fetch user info");
      const me = await meRes.json();

      const websitesRes = await fetch(`${API_URL}/websites`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!websitesRes.ok) throw new Error("Failed to fetch websites");
      const websites = await websitesRes.json();

      if (me?.subscription === "free" && websites.length >= 1) {
        alert("Free plan limited to 1 website. Upgrade to Premium for unlimited monitoring!");
        setLoading(false);
        return;
      }

      const res = await fetch(`${API_URL}/websites`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ url }),
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.error || "Failed to add website");
      }

      await res.json();
      alert("Website added successfully!");
      // navigate back to dashboard where websites will be refreshed on mount
      navigate("/dashboard");
    } catch (err) {
      alert(`Error: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-page" style={{ minHeight: "70vh", paddingTop: "4rem" }}>
      <div className="login-container">
        <div className="login-header">
          <div className="login-logo">
            <img src={logo} alt="Logo" />
            <span>SHIELD</span>
          </div>
          <h2>Add Website</h2>
          <p>Enter the URL you want to monitor</p>
        </div>
        <form className="login-form" onSubmit={handleSubmit}>
          <div className="form-group">
            <label>Website URL</label>
            <input
              type="url"
              placeholder="https://example.com"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              required
            />
          </div>
          <div style={{ marginTop: "1rem" }}>
            <button type="submit" className="btn-login" disabled={loading}>
              {loading ? <span className="spinner" /> : "Add Website"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

export default AddSite;
