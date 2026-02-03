import React from "react";
import { useNavigate } from "react-router-dom";
import "../styles/LandingPage.css";
import logo from '../assets/logo.jpg';
import loginImg from '../assets/logo1.png';

function LandingPage() {
  const navigate = useNavigate();

  const handleGetStarted = () => {
    navigate("/login");
  };

  return (
    <div className="landing-page">
      {/* Header/Navigation */}
      <header className="navbar">
        <div className="navbar-container">
          <div className="logo">
            <img src={logo} alt="Security Logo" />
              <span>SHIELD</span>
          </div>
          <nav className="nav-links ">
            <a href="#features" className="nav-link">Features</a>
            <a href="#pricing" className="nav-link">Pricing</a>
            <a href="#how-it-works" className="nav-link">Work Flow</a>
            <button className="btn-login margin:5px" onClick={() => navigate("/login")}>
              Login
            </button>
          </nav>
        </div>
      </header>

      {/* Hero Section */}
      <section className="hero">
        <div className="hero-content">
          <h1 className="hero-title">Protect You from Cyber Threats</h1>
          <p className="hero-subtitle">Real-time threat detection, instant notifications, and advanced security analytics</p>
          <button className="btn-primary" onClick={handleGetStarted}>Get Started Free</button>
          <p className="hero-subtext">No credit card required • 14-day free trial</p>
        </div>
        <div className="hero-image">
          <div className="security-icon">
            <img src={loginImg} alt="Security" className="security-icon-img" />
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section id="features" className="features">
        <h2>Why Choose ThreatGuard?</h2>
        <div className="features-grid">

          <div className="feature-card">
            <div className="feature-icon">📊</div>
            <h3>Advanced Analytics</h3>
            <p>Detailed threat reports and analytics to understand security patterns</p>
          </div>
          <div className="feature-card">
            <div className="feature-icon">🔍</div>
            <h3>Threat Intelligence</h3>
            <p>Access global threat database with AI-powered threat scoring</p>
          </div>
          
          <div className="feature-card">
            <div className="feature-icon">⚙️</div>
            <h3>Easy Integration</h3>
            <p>Simple one-click setup to start monitoring </p>
          </div>
        </div>
      </section>

      {/* How It Works Section */}
      <section id="how-it-works" className="how-it-works">
        <h2>System Workflow (Overview)</h2>
        <p className="workflow-subtitle">High-level workflow: authenticate, ingest, summarize, store, and notify — designed for clarity and quick understanding.</p>
        <div className="steps-container">
          <div className="workflow-step">
            <div className="icon-tile"><img src={loginImg} alt="login"/></div>
            <h4>Login</h4>
            <p>User / Admin</p>
          </div>

          <div className="connector"><div className="dash"/></div>

          <div className="workflow-step">
            <div className="icon-tile"><img src={loginImg} alt="authenticate"/></div>
            <h4>Authenticate</h4>
            <p>JWT validation</p>
          </div>

          <div className="connector"><div className="dash"/></div>

          <div className="workflow-step">
            <div className="icon-tile"><img src={loginImg} alt="ingest"/></div>
            <h4>Ingest</h4>
            <p>Fetch OTX & other feeds</p>
          </div>

          <div className="connector"><div className="dash"/></div>

          <div className="workflow-step">
            <div className="icon-tile"><img src={loginImg} alt="process"/></div>
            <h4>Process</h4>
            <p>AI summaries & scoring</p>
          </div>

          <div className="connector"><div className="dash"/></div>

          <div className="workflow-step">
            <div className="icon-tile"><img src={loginImg} alt="store"/></div>
            <h4>Store</h4>
            <p>Persist in DB</p>
          </div>

          <div className="connector"><div className="dash"/></div>

          <div className="workflow-step">
            <div className="icon-tile"><img src={loginImg} alt="notify"/></div>
            <h4>Notify</h4>
            <p>Email / Webhook / WebSocket</p>
          </div>
        </div>
      </section>

      {/* Pricing Section */}
      <section id="pricing" className="pricing">
        <h2>Simple Pricing</h2>
        <div className="pricing-grid">
          <div className="pricing-card free">
            <h3>Free</h3>
            <div className="price">$0<span>/month</span></div>
            <ul className="pricing-features">
              <li>✅ Monitor 1</li>
              <li>✅ Basic threat detection</li>
              <li>✅ Email notifications</li>
              <li>❌ Advanced analytics</li>
              <li>❌ Priority support</li>
            </ul>
            <button className="btn-secondary">Get Started</button>
          </div>

          <div className="pricing-card premium">
            <div className="badge">POPULAR</div>
            <h3>Premium</h3>
            <div className="price">$2<span>/month</span></div>
            <ul className="pricing-features">
              <li>✅ Monitor 5 </li>
              <li>✅ Advanced threat detection</li>
              <li>✅ Real-time alerts</li>
              <li>✅ Advanced analytics</li>
              <li>✅ Priority support</li>
            </ul>
            <button className="btn-primary">Upgrade Now</button>
          </div>

          <div className="pricing-card enterprise">
            <h3>Enterprise</h3>
            <div className="price">Custom</div>
            <ul className="pricing-features">
              <li>✅ Everything in Premium</li>
              <li>✅ Custom integrations</li>
              <li>✅ Dedicated support</li>
              <li>✅ API access</li>
              <li>✅ Custom reporting</li>
            </ul>
            <button className="btn-secondary">Contact Sales</button>
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="cta-section">
        <h2>Start Protecting You From Threats Today</h2>
        <p>Join Us Using SHIELD</p>
        <button className="btn-primary btn-large" onClick={handleGetStarted}>
          Get Started Free
        </button>
      </section>

      {/* Footer */}
      <footer className="footer">
        <div className="footer-content">
          <div className="footer-section">
            <h4>SHIELD</h4>
            <p>Comprehensive threat intelligence and  monitoring</p>
          </div>
          <div className="footer-section footer-product">
            <h4>Product</h4>
            <ul>
              <li><a href="#features">Features</a></li>
              <li><a href="#pricing">Pricing</a></li>
              <li><a href="#how-it-works">How It Works</a></li>
            </ul>
          </div>
          
          <div className="footer-section">
            <h4>Contact</h4>
            <p>Email: support@shield.com</p>
            <p>Phone: +1 (555) 123-4567</p>
          </div>
        </div>
        <div className="footer-bottom">
          <p>&copy; 2025 Security.</p>
        </div>
      </footer>
    </div>
  );
}

export default LandingPage;
