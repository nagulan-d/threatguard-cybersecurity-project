import React, { useState, useEffect } from "react";
import { BrowserRouter as Router, Routes, Route, Navigate, useLocation } from "react-router-dom";
import { AnimatePresence } from "framer-motion";
import LandingPage from "./components/LandingPage";
import Login from "./components/Login";
import Register from "./components/RegisterClean";
import ThreatDashboard from "./components/ThreatDashboard";
import UserDashboard from "./components/UserDashboard";
import AdminDashboard from "./components/AdminDashboard";
import AddSite from "./components/AddSite";
import BlockedThreats from "./components/BlockedThreats";
import BlockThreatEmail from "./components/BlockThreatEmail";
import ThreatSubscription from "./components/ThreatSubscription";
import AdminBlockManagement from "./components/AdminBlockManagement";

function AnimatedRoutes({ token, role, handleLogin, handleLogout, isFirstVisit }) {
  const location = useLocation();

  return (
    <AnimatePresence mode="wait">
      <Routes location={location} key={location.pathname}>
        {/* Landing Page - Only shown to unauthenticated users on first visit */}
        <Route
          path="/"
          element={
            !token ? (
              // If the user is not authenticated, always show the landing page first
              <LandingPage />
            ) : role === "admin" ? (
              <Navigate to="/admin" />
            ) : (
              <Navigate to="/dashboard" />
            )
          }
        />

        {/* Login Route */}
        <Route
          path="/login"
          element={!token ? <Login onLogin={handleLogin} /> : <Navigate to={role === "admin" ? "/admin" : "/dashboard"} />}
        />

        {/* Register Route */}
        <Route path="/register" element={<Register />} />

        {/* User Dashboard */}
        <Route
          path="/dashboard"
          element={
            token && role === "user" ? (
              <UserDashboard token={token} logout={handleLogout} />
            ) : (
              <Navigate to="/login" />
            )
          }
        />

        {/* Admin Dashboard */}
        <Route
          path="/admin"
          element={
            token && role === "admin" ? (
              <AdminDashboard token={token} logout={handleLogout} />
            ) : (
              <Navigate to="/login" />
            )
          }
        />

        {/* Threats Dashboard (Legacy - for backward compatibility) */}
        <Route
          path="/threats"
          element={
            token && role === "user" ? (
              <ThreatDashboard token={token} logout={handleLogout} />
            ) : (
              <Navigate to="/login" />
            )
          }
        />

        {/* Add Site Page */}
        <Route
          path="/add-site"
          element={
            token && role === "user" ? (
              <AddSite />
            ) : (
              <Navigate to="/login" />
            )
          }
        />

        {/* Blocked Threats Page */}
        <Route
          path="/blocked-threats"
          element={
            token && role === "user" ? (
              <BlockedThreats />
            ) : (
              <Navigate to="/login" />
            )
          }
        />

        {/* Block Threat Handler (from email link) */}
        <Route
          path="/block-threat"
          element={<BlockThreatEmail />}
        />

        {/* Threat Subscription Settings */}
        <Route
          path="/threat-subscription"
          element={
            token && role === "user" ? (
              <ThreatSubscription />
            ) : (
              <Navigate to="/login" />
            )
          }
        />

        {/* Admin Block Management */}
        <Route
          path="/admin/block-management"
          element={
            token && role === "admin" ? (
              <AdminBlockManagement />
            ) : (
              <Navigate to="/login" />
            )
          }
        />

        {/* Catch-all */}
        <Route path="*" element={<Navigate to="/" />} />
      </Routes>
    </AnimatePresence>
  );
}

function App() {
  // Initialize from localStorage with proper error handling
  const [role, setRole] = useState(() => {
    try {
      return localStorage.getItem("role") || null;
    } catch (e) {
      console.error("Error reading role from localStorage:", e);
      return null;
    }
  });
  
  const [token, setToken] = useState(() => {
    try {
      const storedToken = localStorage.getItem("token");
      console.log("🔐 Initial token from localStorage:", storedToken ? `${storedToken.substring(0, 20)}...` : "NULL");
      return storedToken || null;
    } catch (e) {
      console.error("Error reading token from localStorage:", e);
      return null;
    }
  });
  
  const [isFirstVisit, setIsFirstVisit] = useState(true);

  useEffect(() => {
    // Check if user has been logged in before
    const lastLogin = localStorage.getItem("lastLogin");
    console.log("📅 Last login:", lastLogin);
    console.log("🔑 Current token:", token ? "Present" : "NULL");
    if (token && lastLogin) {
      setIsFirstVisit(false);
    } else if (!token) {
      setIsFirstVisit(true);
    }
  }, [token]);

  const handleLogin = (token, userRole) => {
    console.log("✅ Login successful! Setting token and role");
    console.log("🔑 Token:", token ? `${token.substring(0, 20)}...` : "NULL");
    console.log("👤 Role:", userRole);
    
    localStorage.setItem("token", token);
    localStorage.setItem("role", userRole);
    localStorage.setItem("lastLogin", new Date().toISOString());
    setToken(token);
    setRole(userRole);
    setIsFirstVisit(false);
  };

  const handleLogout = () => {
    console.log("🚪 Logging out, clearing localStorage");
    localStorage.removeItem("token");
    localStorage.removeItem("role");
    localStorage.removeItem("subscription");
    localStorage.removeItem("username");
    setToken(null);
    setRole(null);
    setIsFirstVisit(true); // Show landing page on next visit
  };

  return (
    <Router>
      <AnimatedRoutes
        token={token}
        role={role}
        handleLogin={handleLogin}
        handleLogout={handleLogout}
        isFirstVisit={isFirstVisit}
      />
    </Router>
  );
}

export default App;

