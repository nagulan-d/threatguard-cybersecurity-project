"""
WebSocket Real-time Synchronization for IP Blocking
Enables real-time push notifications of blocking status to admin dashboard
Coordinates blocking events between Windows and Kali VM
"""

import logging
import json
import threading
from datetime import datetime
from typing import Dict, List, Callable, Optional
from enum import Enum

logger = logging.getLogger(__name__)


class BlockingEventType(Enum):
    """Types of blocking events"""
    BLOCK_INITIATED = "block_initiated"
    BLOCK_COMPLETED = "block_completed"
    BLOCK_FAILED = "block_failed"
    UNBLOCK_INITIATED = "unblock_initiated"
    UNBLOCK_COMPLETED = "unblock_completed"
    UNBLOCK_FAILED = "unblock_failed"
    SYNC_STATUS_UPDATE = "sync_status_update"
    HEALTH_STATUS_UPDATE = "health_status_update"
    ERROR = "error"


class BlockingSyncNotifier:
    """Handles WebSocket notifications for blocking sync events"""
    
    def __init__(self):
        """Initialize the notifier"""
        self.subscribers: Dict[str, List[Callable]] = {}  # event_type -> [ callback_functions ]
        self.subscribers_lock = threading.Lock()
        self.event_history: List[Dict] = []
        self.max_history_size = 1000
        logger.info("BlockingSyncNotifier initialized")
    
    def subscribe(self, event_type: str, callback: Callable) -> str:
        """
        Subscribe to blocking events
        
        Args:
            event_type: Type of event to subscribe to (or "*" for all)
            callback: Function to call when event occurs
            
        Returns:
            Subscription ID
        """
        with self.subscribers_lock:
            if event_type not in self.subscribers:
                self.subscribers[event_type] = []
            
            self.subscribers[event_type].append(callback)
            sub_id = f"{event_type}_{len(self.subscribers[event_type])}"
            
            logger.debug(f"Subscription created: {sub_id}")
            return sub_id
    
    def unsubscribe(self, event_type: str, callback: Callable) -> bool:
        """Unsubscribe from events"""
        with self.subscribers_lock:
            if event_type in self.subscribers:
                try:
                    self.subscribers[event_type].remove(callback)
                    logger.debug(f"Unsubscribed from {event_type}")
                    return True
                except ValueError:
                    pass
        
        return False
    
    def notify(self, event_type: str, data: Dict) -> None:
        """
        Notify all subscribers of an event
        
        Args:
            event_type: Type of event
            data: Event data
        """
        event = {
            "event_type": event_type,
            "data": data,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Store in history
        self._add_to_history(event)
        
        # Notify subscribers
        with self.subscribers_lock:
            callbacks = self.subscribers.get(event_type, []) + self.subscribers.get("*", [])
        
        for callback in callbacks:
            try:
                # Call callback asynchronously to prevent blocking
                threading.Thread(target=callback, args=(event,), daemon=True).start()
            except Exception as e:
                logger.error(f"Error notifying subscriber: {e}")
    
    def _add_to_history(self, event: Dict) -> None:
        """Add event to history"""
        self.event_history.append(event)
        
        # Trim history if too large
        if len(self.event_history) > self.max_history_size:
            self.event_history = self.event_history[-self.max_history_size:]
    
    def get_history(self, event_type: Optional[str] = None, limit: int = 50) -> List[Dict]:
        """Get event history"""
        if event_type:
            filtered = [e for e in self.event_history if e["event_type"] == event_type]
            return filtered[-limit:]
        
        return self.event_history[-limit:]
    
    def get_subscriber_count(self, event_type: Optional[str] = None) -> int:
        """Get number of subscribers"""
        with self.subscribers_lock:
            if event_type:
                return len(self.subscribers.get(event_type, []))
            
            return sum(len(callbacks) for callbacks in self.subscribers.values())


class BlockingEventBroadcaster:
    """Broadcasts blocking events to WebSocket clients"""
    
    def __init__(self, notifier: BlockingSyncNotifier):
        """Initialize broadcaster"""
        self.notifier = notifier
        self.connected_clients: Dict[str, Dict] = {}  # client_id -> client_info
        self.clients_lock = threading.Lock()
        logger.info("BlockingEventBroadcaster initialized")
    
    def register_client(self, client_id: str, send_func: Callable, client_info: Dict = None) -> None:
        """Register a WebSocket client"""
        with self.clients_lock:
            self.connected_clients[client_id] = {
                "send": send_func,
                "info": client_info or {},
                "connected_at": datetime.utcnow().isoformat(),
                "event_count": 0
            }
        
        logger.info(f"Client registered: {client_id}")
        
        # Send welcome message
        try:
            send_func({
                "type": "welcome",
                "message": "Connected to ThreatGuard Blocking Sync service",
                "timestamp": datetime.utcnow().isoformat()
            })
        except Exception as e:
            logger.warning(f"Failed to send welcome message: {e}")
    
    def unregister_client(self, client_id: str) -> None:
        """Unregister a WebSocket client"""
        with self.clients_lock:
            if client_id in self.connected_clients:
                del self.connected_clients[client_id]
        
        logger.info(f"Client unregistered: {client_id}")
    
    def broadcast_event(self, event_type: str, data: Dict, exclude_client: Optional[str] = None) -> int:
        """
        Broadcast an event to all connected clients
        
        Returns:
            Number of clients notified
        """
        message = {
            "type": "blocking_event",
            "event_type": event_type,
            "data": data,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        notified = 0
        failed = 0
        
        with self.clients_lock:
            for client_id, client_info in list(self.connected_clients.items()):
                if exclude_client and client_id == exclude_client:
                    continue
                
                try:
                    client_info["send"](message)
                    client_info["event_count"] += 1
                    notified += 1
                except Exception as e:
                    logger.warning(f"Failed to send to client {client_id}: {e}")
                    failed += 1
        
        logger.debug(f"Event '{event_type}' broadcasted to {notified} clients (failed: {failed})")
        return notified
    
    def get_connected_clients_count(self) -> int:
        """Get number of connected clients"""
        with self.clients_lock:
            return len(self.connected_clients)
    
    def get_client_info(self, client_id: str) -> Optional[Dict]:
        """Get information about a specific client"""
        with self.clients_lock:
            return self.connected_clients.get(client_id)
    
    def get_all_clients_info(self) -> Dict:
        """Get information about all connected clients"""
        with self.clients_lock:
            return dict(self.connected_clients)


class RealTimeBlockingCoordinator:
    """Coordinates real-time blocking between systems via WebSocket"""
    
    def __init__(self, notifier: BlockingSyncNotifier = None, broadcaster: BlockingEventBroadcaster = None):
        """Initialize coordinator"""
        self.notifier = notifier or BlockingSyncNotifier()
        self.broadcaster = broadcaster or BlockingEventBroadcaster(self.notifier)
        self.pending_blocks: Dict[str, Dict] = {}  # ip -> block_info
        self.pending_lock = threading.Lock()
        logger.info("RealTimeBlockingCoordinator initialized")
    
    def initiate_block(self, ip: str, threat_data: Dict, initiator: str) -> Dict:
        """
        Initiate a blocking action and notify all connected systems
        
        Args:
            ip: IP to block
            threat_data: Threat information
            initiator: Who initiated the block (username or 'system')
            
        Returns:
            Block tracking info
        """
        block_info = {
            "ip": ip,
            "threat_category": threat_data.get("category", "Unknown"),
            "risk_score": threat_data.get("risk_score", 0),
            "reason": threat_data.get("reason", "Security threat"),
            "initiator": initiator,
            "status": "initiated",
            "windows_status": "pending",
            "linux_status": "pending",
            "initiated_at": datetime.utcnow().isoformat()
        }
        
        with self.pending_lock:
            self.pending_blocks[ip] = block_info
        
        # Notify subscribers
        self.notifier.notify(BlockingEventType.BLOCK_INITIATED.value, block_info)
        
        # Broadcast to WebSocket clients
        self.broadcaster.broadcast_event(BlockingEventType.BLOCK_INITIATED.value, block_info)
        
        logger.info(f"Block initiated for {ip} by {initiator}")
        return block_info
    
    def update_block_status(self, ip: str, windows_status: str = None, linux_status: str = None, 
                           overall_status: str = None, error: str = None) -> Dict:
        """
        Update blocking status and notify clients
        
        Returns:
            Updated block info
        """
        with self.pending_lock:
            block_info = self.pending_blocks.get(ip)
        
        if not block_info:
            logger.warning(f"No pending block found for {ip}")
            return None
        
        # Update status
        if windows_status:
            block_info["windows_status"] = windows_status
        if linux_status:
            block_info["linux_status"] = linux_status
        if overall_status:
            block_info["status"] = overall_status
        if error:
            block_info["error"] = error
        
        block_info["last_update"] = datetime.utcnow().isoformat()
        
        # Determine overall status
        if windows_status and linux_status:
            if windows_status == "blocked" and linux_status == "blocked":
                block_info["status"] = "completed"
            elif windows_status in ["failed", "error"] and linux_status in ["failed", "error"]:
                block_info["status"] = "failed"
            else:
                block_info["status"] = "partial"
        
        # Notify subscribers
        self.notifier.notify(BlockingEventType.SYNC_STATUS_UPDATE.value, block_info)
        
        # Broadcast to WebSocket clients
        self.broadcaster.broadcast_event(BlockingEventType.SYNC_STATUS_UPDATE.value, block_info)
        
        logger.info(f"Block status updated for {ip}: {block_info['status']}")
        
        # Remove from pending if completed
        if block_info["status"] in ["completed", "failed"]:
            with self.pending_lock:
                self.pending_blocks.pop(ip, None)
        
        return block_info
    
    def initiate_unblock(self, ip: str, initiator: str) -> Dict:
        """Initiate an unblocking action"""
        unblock_info = {
            "ip": ip,
            "initiator": initiator,
            "status": "initiated",
            "windows_status": "pending",
            "linux_status": "pending",
            "initiated_at": datetime.utcnow().isoformat()
        }
        
        with self.pending_lock:
            self.pending_blocks[ip] = unblock_info
        
        self.notifier.notify(BlockingEventType.UNBLOCK_INITIATED.value, unblock_info)
        self.broadcaster.broadcast_event(BlockingEventType.UNBLOCK_INITIATED.value, unblock_info)
        
        logger.info(f"Unblock initiated for {ip} by {initiator}")
        return unblock_info
    
    def update_unblock_status(self, ip: str, windows_status: str = None, linux_status: str = None,
                             overall_status: str = None, error: str = None) -> Dict:
        """Update unblocking status"""
        with self.pending_lock:
            unblock_info = self.pending_blocks.get(ip)
        
        if not unblock_info:
            logger.warning(f"No pending unblock found for {ip}")
            return None
        
        if windows_status:
            unblock_info["windows_status"] = windows_status
        if linux_status:
            unblock_info["linux_status"] = linux_status
        if overall_status:
            unblock_info["status"] = overall_status
        if error:
            unblock_info["error"] = error
        
        unblock_info["last_update"] = datetime.utcnow().isoformat()
        
        # Determine overall status
        if windows_status and linux_status:
            if windows_status == "unblocked" and linux_status == "unblocked":
                unblock_info["status"] = "completed"
            elif windows_status in ["failed", "error"] and linux_status in ["failed", "error"]:
                unblock_info["status"] = "failed"
            else:
                unblock_info["status"] = "partial"
        
        self.notifier.notify(BlockingEventType.SYNC_STATUS_UPDATE.value, unblock_info)
        self.broadcaster.broadcast_event(BlockingEventType.SYNC_STATUS_UPDATE.value, unblock_info)
        
        logger.info(f"Unblock status updated for {ip}: {unblock_info['status']}")
        
        if unblock_info["status"] in ["completed", "failed"]:
            with self.pending_lock:
                self.pending_blocks.pop(ip, None)
        
        return unblock_info
    
    def notify_health_status(self, health_data: Dict) -> None:
        """Notify health status to all clients"""
        self.broadcaster.broadcast_event(BlockingEventType.HEALTH_STATUS_UPDATE.value, health_data)
    
    def notify_error(self, ip: str, error_message: str) -> None:
        """Notify error to all clients"""
        error_data = {
            "ip": ip,
            "error": error_message,
            "timestamp": datetime.utcnow().isoformat()
        }
        self.broadcaster.broadcast_event(BlockingEventType.ERROR.value, error_data)
    
    def get_pending_blocks(self) -> Dict:
        """Get all pending blocking operations"""
        with self.pending_lock:
            return dict(self.pending_blocks)


# Global instances
notifier = BlockingSyncNotifier()
broadcaster = BlockingEventBroadcaster(notifier)
realtime_coordinator = RealTimeBlockingCoordinator(notifier, broadcaster)
