import React, { useState } from "react";
import { motion } from "framer-motion";
import { API_URL } from "../config";
import "../App.css";

function Login({ onLogin }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleLogin = async (e) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      const res = await fetch(`${API_URL}/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });

      const data = await res.json();

      if (res.ok) {
        try { localStorage.setItem("token", data.token); } catch (e) {}
        try { localStorage.setItem("role", data.role); } catch (e) {}
        if (onLogin) onLogin(data.token, data.role);
      } else {
        setError(data.error || "Login failed. Please try again.");
      }
    } catch (err) {
      setError("Unable to connect to the server. Check backend.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <motion.div
      className="login-page"
      initial={{ opacity: 0, y: 40 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -40 }}
      transition={{ duration: 0.5 }}
    >
      <div className="login-container">
        <h2>Login</h2>
        <form onSubmit={handleLogin}>
          <input
            type="text"
            placeholder="Username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
            autoFocus
          />
          <input
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
          <button type="submit" disabled={loading}>
            {loading ? "Logging in..." : "Login"}
          </button>
        </form>

        {error && <p className="error">{error}</p>}

        <div style={{ marginTop: "1rem", fontSize: "0.9rem", color: "#555" }}>
          <p><b>Default Admin Credentials:</b></p>
          <p>Username: <code>admin</code></p>
          <p>Password: <code>admin123</code></p>
          <p>Use these to login as admin or register a new user.</p>
        </div>

        <p style={{ marginTop: "1rem", fontSize: "0.9rem" }}>
          Don’t have an account?{" "}
          <a href="/register" style={{ color: "#2ecc71", textDecoration: "none" }}>
            Register here
          </a>
        </p>
      </div>
    </motion.div>
  );
}

export default Login;

