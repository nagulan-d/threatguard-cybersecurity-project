import React, { useEffect, useState, useRef } from 'react';

/**
 * WebSocket Hook for Real-Time IP Blocking Updates
 * Connects to WebSocket server and listens for blocking events
 */
export const useBlockingWebSocket = (token) => {
  const [connected, setConnected] = useState(false);
  const [blockingEvents, setBlockingEvents] = useState([]);
  const [vmAgentStatus, setVmAgentStatus] = useState(null);
  const wsRef = useRef(null);
  const reconnectTimeoutRef = useRef(null);

  const WS_URL = process.env.REACT_APP_WS_URL || 'ws://localhost:8765';
  const RECONNECT_DELAY = 5000; // 5 seconds

  useEffect(() => {
    if (!token) return;

    const connectWebSocket = () => {
      try {
        console.log('[WS] Connecting to WebSocket server...', WS_URL);
        const ws = new WebSocket(WS_URL);
        wsRef.current = ws;

        ws.onopen = () => {
          console.log('[WS] Connection established');
          
          // Send authentication
          ws.send(JSON.stringify({
            token: token,
            client_type: 'admin_dashboard'
          }));
        };

        ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            console.log('[WS] Received:', data);

            switch (data.type) {
              case 'connected':
                console.log('[WS] Authenticated successfully');
                setConnected(true);
                break;

              case 'ip_blocked':
                console.log('[WS] IP Blocked:', data.ip_address);
                setBlockingEvents(prev => [{
                  type: 'blocked',
                  ip: data.ip_address,
                  details: data.details,
                  timestamp: data.timestamp
                }, ...prev].slice(0, 50)); // Keep last 50 events
                
                // Show notification
                if (window.Notification && Notification.permission === 'granted') {
                  new Notification('IP Blocked', {
                    body: `${data.ip_address} - ${data.details?.threat_type || 'High-risk threat'}`,
                    icon: '/shield-icon.png'
                  });
                }
                break;

              case 'ip_unblocked':
                console.log('[WS] IP Unblocked:', data.ip_address);
                setBlockingEvents(prev => [{
                  type: 'unblocked',
                  ip: data.ip_address,
                  details: data.details,
                  timestamp: data.timestamp
                }, ...prev].slice(0, 50));
                break;

              case 'auto_block_triggered':
                console.log('[WS] Auto-block triggered:', data.details);
                setBlockingEvents(prev => [{
                  type: 'auto_block',
                  count: data.details?.count || 0,
                  timestamp: data.timestamp
                }, ...prev].slice(0, 50));
                break;

              case 'vm_agent_status_update':
                console.log('[WS] VM Agent Status:', data);
                setVmAgentStatus({
                  agentId: data.agent_id,
                  status: data.status,
                  blockedCount: data.blocked_ips_count,
                  timestamp: data.timestamp
                });
                break;

              case 'vm_block_confirmed':
                console.log('[WS] VM confirmed block:', data.ip_address);
                setBlockingEvents(prev => [{
                  type: 'vm_confirmed',
                  action: 'block',
                  ip: data.ip_address,
                  success: data.success,
                  message: data.message,
                  timestamp: data.timestamp
                }, ...prev].slice(0, 50));
                break;

              case 'vm_unblock_confirmed':
                console.log('[WS] VM confirmed unblock:', data.ip_address);
                setBlockingEvents(prev => [{
                  type: 'vm_confirmed',
                  action: 'unblock',
                  ip: data.ip_address,
                  success: data.success,
                  message: data.message,
                  timestamp: data.timestamp
                }, ...prev].slice(0, 50));
                break;

              case 'error':
                console.error('[WS] Server error:', data.message);
                break;

              default:
                console.log('[WS] Unknown message type:', data.type);
            }
          } catch (error) {
            console.error('[WS] Error parsing message:', error);
          }
        };

        ws.onerror = (error) => {
          console.error('[WS] WebSocket error:', error);
          setConnected(false);
        };

        ws.onclose = () => {
          console.log('[WS] Connection closed');
          setConnected(false);
          wsRef.current = null;

          // Attempt to reconnect
          console.log(`[WS] Reconnecting in ${RECONNECT_DELAY / 1000}s...`);
          reconnectTimeoutRef.current = setTimeout(() => {
            connectWebSocket();
          }, RECONNECT_DELAY);
        };

      } catch (error) {
        console.error('[WS] Connection error:', error);
        setConnected(false);
      }
    };

    connectWebSocket();

    // Request notification permission
    if (window.Notification && Notification.permission === 'default') {
      Notification.requestPermission();
    }

    // Cleanup
    return () => {
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, [token, WS_URL]);

  // Send ping to keep connection alive
  useEffect(() => {
    if (!connected || !wsRef.current) return;

    const pingInterval = setInterval(() => {
      if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
        wsRef.current.send(JSON.stringify({ type: 'ping' }));
      }
    }, 30000); // Every 30 seconds

    return () => clearInterval(pingInterval);
  }, [connected]);

  const sendMessage = (message) => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(message));
    } else {
      console.warn('[WS] Cannot send message - not connected');
    }
  };

  const requestSync = () => {
    sendMessage({ type: 'request_sync' });
  };

  return {
    connected,
    blockingEvents,
    vmAgentStatus,
    sendMessage,
    requestSync
  };
};


/**
 * Real-Time Blocking Monitor Component
 * Displays live blocking events in the admin dashboard
 */
export const BlockingMonitor = ({ token }) => {
  const { connected, blockingEvents, vmAgentStatus } = useBlockingWebSocket(token);

  return (
    <div className="blocking-monitor">
      <div className="monitor-header">
        <h3>Real-Time Blocking Monitor</h3>
        <div className={`connection-status ${connected ? 'connected' : 'disconnected'}`}>
          <span className="status-dot"></span>
          {connected ? 'Connected' : 'Disconnected'}
        </div>
      </div>

      {vmAgentStatus && (
        <div className="vm-agent-status">
          <h4>VM Agent Status</h4>
          <div className="status-grid">
            <div className="status-item">
              <span className="label">Agent ID:</span>
              <span className="value">{vmAgentStatus.agentId}</span>
            </div>
            <div className="status-item">
              <span className="label">Status:</span>
              <span className={`value status-${vmAgentStatus.status}`}>
                {vmAgentStatus.status}
              </span>
            </div>
            <div className="status-item">
              <span className="label">Blocked IPs:</span>
              <span className="value">{vmAgentStatus.blockedCount}</span>
            </div>
          </div>
        </div>
      )}

      <div className="events-container">
        <h4>Recent Events ({blockingEvents.length})</h4>
        <div className="events-list">
          {blockingEvents.length === 0 ? (
            <p className="no-events">No events yet</p>
          ) : (
            blockingEvents.map((event, index) => (
              <div key={index} className={`event-item event-${event.type}`}>
                <div className="event-icon">
                  {event.type === 'blocked' && '🔒'}
                  {event.type === 'unblocked' && '🔓'}
                  {event.type === 'auto_block' && '⚡'}
                  {event.type === 'vm_confirmed' && '✅'}
                </div>
                <div className="event-content">
                  <div className="event-title">
                    {event.type === 'blocked' && `IP Blocked: ${event.ip}`}
                    {event.type === 'unblocked' && `IP Unblocked: ${event.ip}`}
                    {event.type === 'auto_block' && `Auto-Block: ${event.count} IPs`}
                    {event.type === 'vm_confirmed' && `VM ${event.action}: ${event.ip}`}
                  </div>
                  <div className="event-details">
                    {event.details?.threat_type && (
                      <span>Type: {event.details.threat_type}</span>
                    )}
                    {event.details?.risk_score && (
                      <span>Score: {event.details.risk_score}</span>
                    )}
                    {event.message && <span>{event.message}</span>}
                  </div>
                  <div className="event-time">
                    {new Date(event.timestamp).toLocaleString()}
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      </div>

      <style jsx>{`
        .blocking-monitor {
          background: #fff;
          border-radius: 8px;
          padding: 20px;
          box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }

        .monitor-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 20px;
          padding-bottom: 15px;
          border-bottom: 2px solid #f0f0f0;
        }

        .monitor-header h3 {
          margin: 0;
          color: #333;
        }

        .connection-status {
          display: flex;
          align-items: center;
          gap: 8px;
          padding: 6px 12px;
          border-radius: 20px;
          font-size: 14px;
          font-weight: 500;
        }

        .connection-status.connected {
          background: #e7f5ed;
          color: #2d7a4f;
        }

        .connection-status.disconnected {
          background: #fee;
          color: #c52a2a;
        }

        .status-dot {
          width: 8px;
          height: 8px;
          border-radius: 50%;
          background: currentColor;
          animation: pulse 2s infinite;
        }

        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.5; }
        }

        .vm-agent-status {
          background: #f8f9fa;
          padding: 15px;
          border-radius: 6px;
          margin-bottom: 20px;
        }

        .vm-agent-status h4 {
          margin: 0 0 10px 0;
          font-size: 16px;
          color: #555;
        }

        .status-grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
          gap: 10px;
        }

        .status-item {
          display: flex;
          flex-direction: column;
        }

        .status-item .label {
          font-size: 12px;
          color: #888;
          margin-bottom: 4px;
        }

        .status-item .value {
          font-size: 16px;
          font-weight: 600;
          color: #333;
        }

        .status-item .value.status-active {
          color: #2d7a4f;
        }

        .events-container h4 {
          margin: 0 0 15px 0;
          font-size: 16px;
          color: #555;
        }

        .events-list {
          max-height: 400px;
          overflow-y: auto;
        }

        .no-events {
          text-align: center;
          color: #999;
          padding: 40px;
          font-style: italic;
        }

        .event-item {
          display: flex;
          gap: 12px;
          padding: 12px;
          margin-bottom: 8px;
          border-radius: 6px;
          border-left: 4px solid #ddd;
          background: #f9f9f9;
          transition: all 0.3s ease;
        }

        .event-item:hover {
          background: #f0f0f0;
          transform: translateX(4px);
        }

        .event-item.event-blocked {
          border-left-color: #e74c3c;
          background: #ffebee;
        }

        .event-item.event-unblocked {
          border-left-color: #2ecc71;
          background: #e7f5ed;
        }

        .event-item.event-auto_block {
          border-left-color: #f39c12;
          background: #fff8e1;
        }

        .event-item.event-vm_confirmed {
          border-left-color: #3498db;
          background: #e3f2fd;
        }

        .event-icon {
          font-size: 24px;
          line-height: 1;
        }

        .event-content {
          flex: 1;
        }

        .event-title {
          font-weight: 600;
          color: #333;
          margin-bottom: 4px;
        }

        .event-details {
          display: flex;
          gap: 12px;
          font-size: 13px;
          color: #666;
          margin-bottom: 4px;
        }

        .event-time {
          font-size: 12px;
          color: #999;
        }
      `}</style>
    </div>
  );
};

export default BlockingMonitor;
