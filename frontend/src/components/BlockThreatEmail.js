import React, { useEffect, useState } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import '../styles/BlockThreatEmail.css';

const API_URL = "http://127.0.0.1:5000/api";

export default function BlockThreatEmail() {
    const [searchParams] = useSearchParams();
    const navigate = useNavigate();
    const [status, setStatus] = useState('processing'); // processing, success, error, already_blocked
    const [message, setMessage] = useState('Processing your block request...');
    const [ipAddress, setIpAddress] = useState('');
    const [threatType, setThreatType] = useState('');
    const [riskScore, setRiskScore] = useState(0);
    const [error, setError] = useState('');
    const [blockedAt, setBlockedAt] = useState('');

    useEffect(() => {
        const processBlock = async () => {
            const token = searchParams.get('token');
            
            if (!token) {
                setStatus('error');
                setMessage('❌ No block token provided');
                setError('Invalid link - block token is missing');
                return;
            }

            try {
                console.log('[BLOCK-EMAIL] Sending block request with token:', token);
                
                const response = await fetch(`${API_URL}/user/block-threat`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ token })
                });

                const data = await response.json();
                console.log('[BLOCK-EMAIL] Response:', data);

                if (response.ok) {
                    if (data.already_blocked) {
                        setStatus('already_blocked');
                        setMessage('⚠️ IP Already Blocked');
                        setIpAddress(data.ip_address);
                        setBlockedAt(data.blocked_at);
                    } else {
                        setStatus('success');
                        setMessage('✅ IP Successfully Blocked');
                        setIpAddress(data.ip_address);
                        setThreatType(data.threat_type);
                        setRiskScore(data.risk_score);
                        setBlockedAt(data.blocked_at);
                    }
                } else {
                    setStatus('error');
                    setMessage('❌ Block Failed');
                    setError(data.error || 'Failed to process block request');
                }
            } catch (err) {
                console.error('[BLOCK-EMAIL] Error:', err);
                setStatus('error');
                setMessage('❌ Connection Error');
                setError(`Failed to reach server: ${err.message}`);
            }
        };

        processBlock();
    }, [searchParams]);

    const getRiskColor = (score) => {
        if (score >= 75) return '#dc3545';  // Red - High Risk
        if (score >= 50) return '#ffc107';  // Yellow - Medium Risk
        return '#28a745';  // Green - Low Risk
    };

    const handleDone = () => {
        navigate('/dashboard');
    };

    return (
        <div className="block-threat-container">
            <motion.div 
                className="block-threat-card"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.5 }}
            >
                {/* Status Icon and Message */}
                <motion.div 
                    className={`status-icon status-${status}`}
                    animate={{ scale: status === 'processing' ? [1, 1.2, 1] : 1 }}
                    transition={{ repeat: status === 'processing' ? Infinity : 0, duration: 1 }}
                >
                    {status === 'processing' && '⏳'}
                    {status === 'success' && '✅'}
                    {status === 'error' && '❌'}
                    {status === 'already_blocked' && '⚠️'}
                </motion.div>

                <h1 className={`message message-${status}`}>{message}</h1>

                {/* Success State */}
                {status === 'success' && (
                    <motion.div 
                        className="block-details success"
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        transition={{ delay: 0.3 }}
                    >
                        <div className="detail-item">
                            <span className="label">IP Address:</span>
                            <code className="ip-address">{ipAddress}</code>
                        </div>
                        <div className="detail-item">
                            <span className="label">Threat Type:</span>
                            <span className="value">{threatType}</span>
                        </div>
                        <div className="detail-item">
                            <span className="label">Risk Score:</span>
                            <div className="risk-badge" style={{ backgroundColor: getRiskColor(riskScore) }}>
                                {riskScore}/100
                            </div>
                        </div>
                        <div className="detail-item">
                            <span className="label">Blocked At:</span>
                            <span className="value">{new Date(blockedAt).toLocaleString()}</span>
                        </div>
                        <p className="confirmation-text">
                            This IP address is now blocked on your environment and cannot access your systems.
                        </p>
                    </motion.div>
                )}

                {/* Already Blocked State */}
                {status === 'already_blocked' && (
                    <motion.div 
                        className="block-details already-blocked"
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        transition={{ delay: 0.3 }}
                    >
                        <div className="detail-item">
                            <span className="label">IP Address:</span>
                            <code className="ip-address">{ipAddress}</code>
                        </div>
                        <div className="detail-item">
                            <span className="label">Previously Blocked:</span>
                            <span className="value">{new Date(blockedAt).toLocaleString()}</span>
                        </div>
                        <p className="confirmation-text">
                            This IP was already blocked by you previously. No further action is needed.
                        </p>
                    </motion.div>
                )}

                {/* Error State */}
                {status === 'error' && (
                    <motion.div 
                        className="block-details error"
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        transition={{ delay: 0.3 }}
                    >
                        <p className="error-text">{error}</p>
                        <div className="error-details">
                            <p><strong>Common Issues:</strong></p>
                            <ul>
                                <li>Link has expired (24-hour token limit)</li>
                                <li>Token was already used</li>
                                <li>Invalid token format</li>
                                <li>Server connection error</li>
                            </ul>
                            <p>If the problem persists, please request a new threat notification email.</p>
                        </div>
                    </motion.div>
                )}

                {/* Processing State */}
                {status === 'processing' && (
                    <motion.div 
                        className="processing-details"
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                    >
                        <div className="spinner"></div>
                        <p>Validating token and processing your block request...</p>
                    </motion.div>
                )}

                {/* Action Buttons */}
                <motion.div 
                    className="button-group"
                    initial={{ opacity: 0 }}
                    animate={{ opacity: status !== 'processing' ? 1 : 0 }}
                    transition={{ delay: 0.5 }}
                >
                    {status === 'success' && (
                        <>
                            <button className="btn btn-primary" onClick={handleDone}>
                                View Dashboard
                            </button>
                            <a href="mailto:support@threatguard.local" className="btn btn-secondary">
                                Contact Support
                            </a>
                        </>
                    )}
                    {status === 'already_blocked' && (
                        <button className="btn btn-primary" onClick={handleDone}>
                            Return to Dashboard
                        </button>
                    )}
                    {status === 'error' && (
                        <>
                            <button className="btn btn-primary" onClick={() => window.location.reload()}>
                                Retry
                            </button>
                            <button className="btn btn-secondary" onClick={() => navigate('/dashboard')}>
                                Return to Dashboard
                            </button>
                        </>
                    )}
                </motion.div>

                {/* Info Section */}
                <motion.div 
                    className="info-section"
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ delay: 0.7 }}
                >
                    <h3>📋 What Happens Next?</h3>
                    <ul>
                        <li>✓ Your IP block has been recorded in the audit log</li>
                        <li>✓ The admin team will be notified of your action</li>
                        <li>✓ You'll receive a confirmation email</li>
                        <li>✓ Manage all your blocks from your dashboard</li>
                    </ul>
                </motion.div>
            </motion.div>
        </div>
    );
}
