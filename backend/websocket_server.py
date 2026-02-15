"""
WebSocket Server for Real-Time IP Blocking Synchronization
Provides instant updates to admin dashboard when IPs are blocked/unblocked
Supports bi-directional communication for immediate firewall sync
"""

import asyncio
import json
import logging
from datetime import datetime
from typing import Set, Dict, Any, Optional
import websockets
from websockets.server import WebSocketServerProtocol
import jwt
import os
from dotenv import load_dotenv

load_dotenv()

# Configuration
WS_HOST = os.getenv("WS_HOST", "0.0.0.0")
WS_PORT = int(os.getenv("WS_PORT", 8765))
SECRET_KEY = os.getenv("SECRET_KEY", "default_secret")

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [WS] %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class WebSocketManager:
    """Manages WebSocket connections and broadcasts"""
    
    def __init__(self):
        self.admin_connections: Set[WebSocketServerProtocol] = set()
        self.vm_agents: Set[WebSocketServerProtocol] = set()
        self.user_connections: Dict[str, WebSocketServerProtocol] = {}
        
    async def register_admin(self, websocket: WebSocketServerProtocol, user_id: str):
        """Register an admin connection"""
        self.admin_connections.add(websocket)
        logger.info(f"Admin connected (User ID: {user_id}). Total admins: {len(self.admin_connections)}")
        
        # Send welcome message
        await websocket.send(json.dumps({
            "type": "connected",
            "role": "admin",
            "message": "Connected to IP blocking WebSocket server",
            "timestamp": datetime.utcnow().isoformat()
        }))
    
    async def register_vm_agent(self, websocket: WebSocketServerProtocol, agent_id: str):
        """Register a VM agent connection"""
        self.vm_agents.add(websocket)
        logger.info(f"VM Agent connected (ID: {agent_id}). Total agents: {len(self.vm_agents)}")
        
        await websocket.send(json.dumps({
            "type": "connected",
            "role": "vm_agent",
            "message": "VM agent connected to sync server",
            "timestamp": datetime.utcnow().isoformat()
        }))
    
    async def register_user(self, websocket: WebSocketServerProtocol, user_id: str):
        """Register a regular user connection"""
        self.user_connections[user_id] = websocket
        logger.info(f"User connected (ID: {user_id}). Total users: {len(self.user_connections)}")
        
        await websocket.send(json.dumps({
            "type": "connected",
            "role": "user",
            "message": "Connected to threat monitoring",
            "timestamp": datetime.utcnow().isoformat()
        }))
    
    async def unregister(self, websocket: WebSocketServerProtocol):
        """Remove a disconnected client"""
        if websocket in self.admin_connections:
            self.admin_connections.remove(websocket)
            logger.info(f"Admin disconnected. Remaining: {len(self.admin_connections)}")
        elif websocket in self.vm_agents:
            self.vm_agents.remove(websocket)
            logger.info(f"VM agent disconnected. Remaining: {len(self.vm_agents)}")
        else:
            # Check user connections
            user_id = None
            for uid, ws in self.user_connections.items():
                if ws == websocket:
                    user_id = uid
                    break
            if user_id:
                del self.user_connections[user_id]
                logger.info(f"User {user_id} disconnected. Remaining: {len(self.user_connections)}")
    
    async def broadcast_to_admins(self, message: Dict[str, Any]):
        """Broadcast message to all connected admins"""
        if not self.admin_connections:
            logger.warning("No admin connections to broadcast to")
            return
        
        message_json = json.dumps(message)
        disconnected = set()
        
        for websocket in self.admin_connections:
            try:
                await websocket.send(message_json)
            except websockets.exceptions.ConnectionClosed:
                disconnected.add(websocket)
            except Exception as e:
                logger.error(f"Error broadcasting to admin: {e}")
                disconnected.add(websocket)
        
        # Clean up disconnected clients
        for ws in disconnected:
            await self.unregister(ws)
    
    async def broadcast_to_vm_agents(self, message: Dict[str, Any]):
        """Broadcast blocking commands to all VM agents"""
        if not self.vm_agents:
            logger.warning("No VM agents connected")
            return
        
        message_json = json.dumps(message)
        disconnected = set()
        
        for websocket in self.vm_agents:
            try:
                await websocket.send(message_json)
                logger.info(f"Sent blocking command to VM agent")
            except websockets.exceptions.ConnectionClosed:
                disconnected.add(websocket)
            except Exception as e:
                logger.error(f"Error broadcasting to VM agent: {e}")
                disconnected.add(websocket)
        
        # Clean up disconnected agents
        for ws in disconnected:
            await self.unregister(ws)
    
    async def send_to_user(self, user_id: str, message: Dict[str, Any]):
        """Send message to specific user"""
        websocket = self.user_connections.get(user_id)
        if not websocket:
            logger.warning(f"User {user_id} not connected")
            return
        
        try:
            await websocket.send(json.dumps(message))
        except websockets.exceptions.ConnectionClosed:
            await self.unregister(websocket)
        except Exception as e:
            logger.error(f"Error sending to user {user_id}: {e}")
    
    async def notify_ip_blocked(self, ip_address: str, details: Dict[str, Any]):
        """Notify all clients about a new IP block"""
        message = {
            "type": "ip_blocked",
            "ip_address": ip_address,
            "details": details,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Notify admins
        await self.broadcast_to_admins(message)
        
        # Send block command to VM agents
        await self.broadcast_to_vm_agents({
            "type": "block_ip",
            "ip_address": ip_address,
            "reason": details.get("reason", "High-risk threat detected"),
            "threat_type": details.get("threat_type", "Unknown"),
            "risk_score": details.get("risk_score", 0),
            "timestamp": datetime.utcnow().isoformat()
        })
        
        logger.info(f"Broadcasted IP block notification: {ip_address}")
    
    async def notify_ip_unblocked(self, ip_address: str, details: Dict[str, Any]):
        """Notify all clients about an IP unblock"""
        message = {
            "type": "ip_unblocked",
            "ip_address": ip_address,
            "details": details,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Notify admins
        await self.broadcast_to_admins(message)
        
        # Send unblock command to VM agents
        await self.broadcast_to_vm_agents({
            "type": "unblock_ip",
            "ip_address": ip_address,
            "timestamp": datetime.utcnow().isoformat()
        })
        
        logger.info(f"Broadcasted IP unblock notification: {ip_address}")
    
    async def notify_auto_block_triggered(self, details: Dict[str, Any]):
        """Notify admins that auto-blocking was triggered"""
        message = {
            "type": "auto_block_triggered",
            "details": details,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        await self.broadcast_to_admins(message)
        logger.info(f"Notified auto-block trigger: {details.get('count', 0)} IPs")

# Global manager instance
ws_manager = WebSocketManager()


def verify_token(token: str) -> Dict[str, Any]:
    """Verify JWT token and extract payload"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        raise ValueError("Token expired")
    except jwt.InvalidTokenError:
        raise ValueError("Invalid token")


async def handle_client(websocket: WebSocketServerProtocol, path: Optional[str] = None):
    """Handle WebSocket client connection"""
    client_id = None
    client_role = None
    
    try:
        # Wait for authentication message
        auth_message = await asyncio.wait_for(websocket.recv(), timeout=10.0)
        auth_data = json.loads(auth_message)
        
        # Verify token
        token = auth_data.get("token")
        if not token:
            await websocket.send(json.dumps({"error": "No token provided"}))
            return
        
        try:
            payload = verify_token(token)
            client_id = payload.get("user_id")
            client_role = payload.get("role", "user")
        except ValueError as e:
            await websocket.send(json.dumps({"error": str(e)}))
            return
        
        # Check if this is a VM agent (special authentication)
        if auth_data.get("client_type") == "vm_agent":
            agent_id = auth_data.get("agent_id", client_id)
            await ws_manager.register_vm_agent(websocket, agent_id)
            client_role = "vm_agent"
        elif client_role == "admin":
            await ws_manager.register_admin(websocket, client_id)
        else:
            await ws_manager.register_user(websocket, client_id)
        
        logger.info(f"Client authenticated: ID={client_id}, Role={client_role}")
        
        # Listen for messages
        async for message in websocket:
            try:
                data = json.loads(message)
                await handle_message(websocket, data, client_id, client_role)
            except json.JSONDecodeError:
                await websocket.send(json.dumps({"error": "Invalid JSON"}))
            except Exception as e:
                logger.error(f"Error handling message: {e}")
                await websocket.send(json.dumps({"error": str(e)}))
    
    except asyncio.TimeoutError:
        logger.warning("Client authentication timeout")
    except websockets.exceptions.ConnectionClosed:
        logger.info(f"Client disconnected: {client_id}")
    except Exception as e:
        logger.error(f"Error in client handler: {e}")
    finally:
        await ws_manager.unregister(websocket)


async def handle_message(websocket: WebSocketServerProtocol, data: Dict[str, Any], 
                         client_id: str, client_role: str):
    """Handle incoming WebSocket messages"""
    msg_type = data.get("type")
    
    if msg_type == "ping":
        await websocket.send(json.dumps({"type": "pong", "timestamp": datetime.utcnow().isoformat()}))
    
    elif msg_type == "vm_agent_status":
        # VM agent reporting status
        if client_role == "vm_agent":
            logger.info(f"VM agent status: {data.get('status')}")
            # Broadcast status to admins
            await ws_manager.broadcast_to_admins({
                "type": "vm_agent_status_update",
                "agent_id": client_id,
                "status": data.get("status"),
                "blocked_ips_count": data.get("blocked_ips_count", 0),
                "timestamp": datetime.utcnow().isoformat()
            })
    
    elif msg_type == "block_confirmation":
        # VM agent confirming successful block
        if client_role == "vm_agent":
            logger.info(f"VM agent confirmed block: {data.get('ip_address')}")
            await ws_manager.broadcast_to_admins({
                "type": "vm_block_confirmed",
                "ip_address": data.get("ip_address"),
                "agent_id": client_id,
                "success": data.get("success", True),
                "message": data.get("message", ""),
                "timestamp": datetime.utcnow().isoformat()
            })
    
    elif msg_type == "unblock_confirmation":
        # VM agent confirming successful unblock
        if client_role == "vm_agent":
            logger.info(f"VM agent confirmed unblock: {data.get('ip_address')}")
            await ws_manager.broadcast_to_admins({
                "type": "vm_unblock_confirmed",
                "ip_address": data.get("ip_address"),
                "agent_id": client_id,
                "success": data.get("success", True),
                "message": data.get("message", ""),
                "timestamp": datetime.utcnow().isoformat()
            })
    
    elif msg_type == "request_sync":
        # Client requesting full sync
        if client_role == "admin":
            logger.info(f"Admin {client_id} requested full sync")
            # This would trigger a full sync from database
            # Implementation in backend API
    
    elif msg_type == "broadcast_block":
        if client_role == "admin":
            ip_address = data.get("ip_address")
            details = data.get("details", {})
            if not ip_address:
                await websocket.send(json.dumps({"error": "Missing ip_address"}))
                return
            await ws_manager.notify_ip_blocked(ip_address, details)
            logger.info(f"Admin broadcasted block for {ip_address}")
    
    elif msg_type == "broadcast_unblock":
        if client_role == "admin":
            ip_address = data.get("ip_address")
            details = data.get("details", {})
            if not ip_address:
                await websocket.send(json.dumps({"error": "Missing ip_address"}))
                return
            await ws_manager.notify_ip_unblocked(ip_address, details)
            logger.info(f"Admin broadcasted unblock for {ip_address}")
    
    else:
        logger.warning(f"Unknown message type: {msg_type}")


async def start_server():
    """Start the WebSocket server"""
    logger.info(f"Starting WebSocket server on {WS_HOST}:{WS_PORT}")
    
    async with websockets.serve(handle_client, WS_HOST, WS_PORT):
        logger.info(f"✅ WebSocket server running on ws://{WS_HOST}:{WS_PORT}")
        await asyncio.Future()  # Run forever


def run_websocket_server():
    """Main entry point for the WebSocket server"""
    try:
        asyncio.run(start_server())
    except KeyboardInterrupt:
        logger.info("WebSocket server shutting down...")
    except Exception as e:
        logger.error(f"WebSocket server error: {e}")
        raise


if __name__ == "__main__":
    run_websocket_server()
