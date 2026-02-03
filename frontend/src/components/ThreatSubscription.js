import React, { useState, useEffect } from 'react';
import '../styles/ThreatSubscription.css';

function ThreatSubscription() {
  const [subscriptionStatus, setSubscriptionStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [email, setEmail] = useState('');
  const [minRiskScore, setMinRiskScore] = useState(75);
  const [message, setMessage] = useState({ type: '', text: '' });

  useEffect(() => {
    fetchSubscriptionStatus();
  }, []);

  const fetchSubscriptionStatus = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch('http://localhost:5000/api/subscription-status', {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (response.ok) {
        const data = await response.json();
        setSubscriptionStatus(data);
        if (data.subscribed) {
          setEmail(data.email || '');
          setMinRiskScore(data.min_risk_score || 75);
        }
      }
    } catch (err) {
      console.error('Error fetching subscription status:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleSubscribe = async (e) => {
    e.preventDefault();
    setMessage({ type: '', text: '' });

    try {
      const token = localStorage.getItem('token');
      const response = await fetch('http://localhost:5000/api/subscribe-threats', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ email, min_risk_score: minRiskScore })
      });

      const data = await response.json();

      if (response.ok) {
        setMessage({ type: 'success', text: data.message });
        fetchSubscriptionStatus();
      } else {
        setMessage({ type: 'error', text: data.error || 'Subscription failed' });
      }
    } catch (err) {
      console.error('Error subscribing:', err);
      setMessage({ type: 'error', text: 'Network error. Please try again.' });
    }
  };

  const handleUnsubscribe = async () => {
    if (!window.confirm('Are you sure you want to unsubscribe from threat notifications?')) {
      return;
    }

    try {
      const token = localStorage.getItem('token');
      const response = await fetch('http://localhost:5000/api/unsubscribe-threats', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      const data = await response.json();

      if (response.ok) {
        setMessage({ type: 'success', text: data.message });
        fetchSubscriptionStatus();
      } else {
        setMessage({ type: 'error', text: data.error || 'Unsubscribe failed' });
      }
    } catch (err) {
      console.error('Error unsubscribing:', err);
      setMessage({ type: 'error', text: 'Network error. Please try again.' });
    }
  };

  if (loading) {
    return (
      <div className="subscription-container">
        <div className="loading">Loading subscription status...</div>
      </div>
    );
  }

  return (
    <div className="subscription-container">
      <div className="subscription-header">
        <h2>📧 Threat Email Notifications</h2>
        <p>Get instant email alerts for high-risk threats with one-click blocking</p>
      </div>

      {message.text && (
        <div className={`message ${message.type}`}>
          {message.type === 'success' ? '✅' : '⚠️'} {message.text}
        </div>
      )}

      {subscriptionStatus?.subscribed ? (
        <div className="subscription-active">
          <div className="active-badge">
            <span className="badge-icon">✅</span>
            <span className="badge-text">Active Subscription</span>
          </div>

          <div className="subscription-details">
            <div className="detail-item">
              <span className="detail-label">Email:</span>
              <span className="detail-value">{subscriptionStatus.email}</span>
            </div>
            <div className="detail-item">
              <span className="detail-label">Minimum Risk Score:</span>
              <span className="detail-value">{subscriptionStatus.min_risk_score}/100</span>
            </div>
            {subscriptionStatus.subscribed_at && (
              <div className="detail-item">
                <span className="detail-label">Subscribed Since:</span>
                <span className="detail-value">
                  {new Date(subscriptionStatus.subscribed_at).toLocaleDateString()}
                </span>
              </div>
            )}
          </div>

          <div className="subscription-info">
            <h3>How it works:</h3>
            <ul>
              <li>📨 You'll receive email alerts for threats with risk score ≥ {subscriptionStatus.min_risk_score}</li>
              <li>🛡️ Each email includes a secure "Block IP" button</li>
              <li>✅ One-click blocking protects your environment instantly</li>
              <li>📬 Confirmation emails sent after successful blocks</li>
            </ul>
          </div>

          <div className="subscription-actions">
            <button className="btn-unsubscribe" onClick={handleUnsubscribe}>
              Unsubscribe
            </button>
          </div>

          <div className="update-settings">
            <h3>Update Notification Settings</h3>
            <form onSubmit={handleSubscribe}>
              <div className="form-group">
                <label htmlFor="email">Email Address:</label>
                <input
                  type="email"
                  id="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                />
              </div>

              <div className="form-group">
                <label htmlFor="minRiskScore">
                  Minimum Risk Score: <strong>{minRiskScore}</strong>/100
                </label>
                <input
                  type="range"
                  id="minRiskScore"
                  min="0"
                  max="100"
                  step="5"
                  value={minRiskScore}
                  onChange={(e) => setMinRiskScore(parseInt(e.target.value))}
                />
                <div className="score-labels">
                  <span>Low (0)</span>
                  <span>Medium (50)</span>
                  <span>High (75)</span>
                  <span>Critical (100)</span>
                </div>
              </div>

              <button type="submit" className="btn-update">
                Update Settings
              </button>
            </form>
          </div>
        </div>
      ) : (
        <div className="subscription-inactive">
          <div className="subscription-benefits">
            <h3>🎯 Benefits of Email Notifications:</h3>
            <ul>
              <li>⚡ <strong>Real-time Alerts:</strong> Get notified immediately when high-risk threats are detected</li>
              <li>🛡️ <strong>One-Click Protection:</strong> Block malicious IPs directly from your email</li>
              <li>🎯 <strong>Customizable:</strong> Set your own risk threshold for notifications</li>
              <li>📊 <strong>Stay Informed:</strong> Detailed threat information in every email</li>
              <li>✅ <strong>Confirmation Emails:</strong> Get notified when IPs are successfully blocked</li>
            </ul>
          </div>

          <form className="subscribe-form" onSubmit={handleSubscribe}>
            <h3>Subscribe to Threat Notifications</h3>

            <div className="form-group">
              <label htmlFor="email">Email Address:</label>
              <input
                type="email"
                id="email"
                placeholder="your.email@example.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
              />
              <small>You'll receive notifications at this email address</small>
            </div>

            <div className="form-group">
              <label htmlFor="minRiskScore">
                Minimum Risk Score: <strong>{minRiskScore}</strong>/100
              </label>
              <input
                type="range"
                id="minRiskScore"
                min="0"
                max="100"
                step="5"
                value={minRiskScore}
                onChange={(e) => setMinRiskScore(parseInt(e.target.value))}
              />
              <div className="score-labels">
                <span>Low (0)</span>
                <span>Medium (50)</span>
                <span>High (75)</span>
                <span>Critical (100)</span>
              </div>
              <small>Only receive notifications for threats with score ≥ {minRiskScore}</small>
            </div>

            <button type="submit" className="btn-subscribe">
              Subscribe Now
            </button>
          </form>
        </div>
      )}
    </div>
  );
}

export default ThreatSubscription;
