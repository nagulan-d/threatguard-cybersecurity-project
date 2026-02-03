import React, { useState } from "react";
import { motion } from "framer-motion";
import { API_URL } from "../config";
import "../App.css";
import "../styles/Login.css";

export default function RegisterClean() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [email, setEmail] = useState("");
  const [phone, setPhone] = useState("");
  const [role, setRole] = useState("user");
  const [subscribed, setSubscribed] = useState(true);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      const res = await fetch(`${API_URL}/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password, email, phone, role, subscribed }),
      });
      const data = await res.json();
      if (res.ok) {
        window.location.href = `/login?username=${encodeURIComponent(username)}`;
      } else {
        setError(data.error || "Registration failed.");
      }
    } catch (err) {
      setError("Unable to connect to the server.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <motion.div
      className="register-page"
      initial={{ opacity: 0, y: 40 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -40 }}
      transition={{ duration: 0.5 }}
    >
      <div className="login-container">
        <h2>Register</h2>
        <form onSubmit={handleSubmit}>
          <input
            type="text"
            placeholder="Username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
            autoFocus
          />

          <input
            type="email"
            placeholder="Email Address"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />

          <input
            type="tel"
            placeholder="Phone Number"
            value={phone}
            onChange={(e) => setPhone(e.target.value)}
          />

          <input
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />

          <select
            value={role}
            onChange={(e) => setRole(e.target.value)}
            style={{ marginTop: 8, width: '100%', padding: '10px', borderRadius: 8 }}
          >
            <option value="user">User</option>
            <option value="admin">Administrator</option>
          </select>

          <div className="login-divider" style={{ marginTop: 12 }} />

          <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginTop: 8 }}>
            <label className="toggle-switch">
              <input
                type="checkbox"
                checked={subscribed}
                onChange={(e) => setSubscribed(e.target.checked)}
                aria-label="Subscribe to notifications"
              />
              <span className="track"><span className="thumb" /></span>
            </label>
            <div style={{ color: '#6b7280', fontSize: 14 }}>Get email notifications for high-risk threats</div>
          </div>

          <button type="submit" disabled={loading} className="btn-login" style={{ marginTop: 16 }}>
            {loading ? "Creating..." : "Register"}
          </button>
        </form>

        {error && <p className="error">{error}</p>}

        <p style={{ marginTop: "1rem", fontSize: "0.9rem" }}>
          Already have an account? {" "}
          <a href="/login" style={{ color: "#2ecc71", textDecoration: "none" }}>
            Login
          </a>
        </p>
      </div>
    </motion.div>
  );
}
