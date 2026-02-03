import React, { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import '../styles/BlockThreatHandler.css';

function BlockThreatHandler() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const [status, setStatus] = useState('processing');
  const [message, setMessage] = useState('');
  const [threatInfo, setThreatInfo] = useState(null);

  useEffect(() => {
    const token = searchParams.get('token');
    
    if (!token) {
      setStatus('error');
      setMessage('Invalid or missing block token');
      return;
    }

    // Process via email token first (no login required). If it fails due to auth,
    // we'll retry with JWT if available.
    handleBlockThreat(token);
  }, [searchParams, navigate]);

  const handleBlockThreat = async (blockToken) => {
    try {
      // First attempt: token-only (server now supports email-token auth)
      let response = await fetch('http://localhost:5000/api/block-threat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: blockToken })
      });

      let data = await response.json();

      // If unauthorized and JWT exists, retry with Authorization header
      if (!response.ok && response.status === 401) {
        const jwtToken = localStorage.getItem('token');
        if (jwtToken) {
          response = await fetch('http://localhost:5000/api/block-threat', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Authorization': `Bearer ${jwtToken}`
            },
            body: JSON.stringify({ token: blockToken })
          });
          data = await response.json();
        }
      }

      if (response.ok) {
        setStatus('success');
        setMessage('IP address successfully blocked!');
        setThreatInfo(data.blocked_threat);
        
        // Redirect to dashboard after 3 seconds
        setTimeout(() => {
          navigate('/dashboard');
        }, 3000);
      } else {
        setStatus('error');
        setMessage(data.error || 'Failed to block IP address');
      }
    } catch (err) {
      console.error('Error blocking threat:', err);
      setStatus('error');
      setMessage('Network error. Please try again.');
    }
  };

  const renderContent = () => {
    switch (status) {
      case 'processing':
        return (
          <div className="status-content processing">
            <div className="spinner-large"></div>
            <h2>Processing Your Request</h2>
            <p>Blocking the malicious IP address...</p>
          </div>
        );

      case 'success':
        return (
          <div className="status-content success">
            <div className="success-icon">✅</div>
            <h2>IP Successfully Blocked!</h2>
            <p>{message}</p>
            
            {threatInfo && (
              <div className="threat-info-card">
                <h3>Blocked Threat Details</h3>
                <div className="info-row">
                  <span className="info-label">IP Address:</span>
                  <code className="info-value">{threatInfo.ip_address}</code>
                </div>
                <div className="info-row">
                  <span className="info-label">Threat Type:</span>
                  <span className="info-value">{threatInfo.threat_type}</span>
                </div>
                <div className="info-row">
                  <span className="info-label">Risk Category:</span>
                  <span className={`info-value badge-${threatInfo.risk_category?.toLowerCase()}`}>
                    {threatInfo.risk_category}
                  </span>
                </div>
                <div className="info-row">
                  <span className="info-label">Blocked At:</span>
                  <span className="info-value">
                    {new Date(threatInfo.blocked_at).toLocaleString()}
                  </span>
                </div>
              </div>
            )}

            <div className="redirect-notice">
              <p>🔄 Redirecting to your dashboard in 3 seconds...</p>
              <button className="btn-primary" onClick={() => navigate('/dashboard')}>
                Go to Dashboard Now
              </button>
            </div>
          </div>
        );

      case 'error':
        return (
          <div className="status-content error">
            <div className="error-icon">❌</div>
            <h2>Block Failed</h2>
            <p>{message}</p>
            
            <div className="error-actions">
              <button className="btn-secondary" onClick={() => navigate('/dashboard')}>
                Go to Dashboard
              </button>
              <button className="btn-primary" onClick={() => window.location.reload()}>
                Try Again
              </button>
            </div>
          </div>
        );

      default:
        return null;
    }
  };

  return (
    <div className="block-threat-handler">
      <div className="handler-container">
        {renderContent()}
      </div>
    </div>
  );
}

export default BlockThreatHandler;
