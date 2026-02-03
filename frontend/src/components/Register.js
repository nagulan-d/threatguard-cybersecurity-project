import React, { useState } from "react";
import { motion } from "framer-motion";
import "../App.css";
import "../styles/Login.css";

export default function Register() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [email, setEmail] = useState("");
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      const res = await fetch("http://127.0.0.1:5000/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password, email }),
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
      import React, { useState } from "react";
      import { motion } from "framer-motion";
      import { API_URL } from "../config";
      import "../App.css";
      import "../styles/Login.css";

      export default function Register() {
        const [username, setUsername] = useState("");
        const [password, setPassword] = useState("");
        const [email, setEmail] = useState("");
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
              body: JSON.stringify({ username, password, email }),
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
              <h2>Create Account</h2>
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
                  placeholder="Email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                />
                <input
                  type="password"
                  placeholder="Password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                />

                <button type="submit" disabled={loading}>
                  {loading ? "Creating..." : "Create Account"}
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
      animate={{ opacity: 1, y: 0 }}

      exit={{ opacity: 0, y: -40 }}
