"""
Secure API Endpoints for IP Blocking Synchronization
REST API for coordinating IP blocking across Windows and Linux systems
Includes authentication, input validation, and rate limiting
"""

from flask import Blueprint, request, jsonify, current_app
from functools import wraps
from datetime import datetime, timedelta
import jwt
import logging
import os

logger = logging.getLogger(__name__)


def create_blocking_sync_blueprint(sync_service=None, coordinator=None):
    """Create Flask blueprint for blocking sync API"""
    
    blocking_api = Blueprint('blocking_api', __name__, url_prefix='/api/blocking')
    
    API_TOKEN = os.getenv("BLOCKING_API_TOKEN", "threatguard_sync_token_secret")
    
    def require_api_token(f):
        """Decorator to verify API token"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            token = None
            
            # Check Authorization header
            if 'Authorization' in request.headers:
                auth_header = request.headers.get('Authorization')
                try:
                    token = auth_header.split(" ")[1]
                except IndexError:
                    return jsonify({"error": "Invalid authorization header"}), 401
            
            # Check query parameter as fallback
            if not token:
                token = request.args.get('token')
            
            if not token:
                return jsonify({"error": "Missing API token"}), 401
            
            if token != API_TOKEN:
                logger.warning(f"Invalid API token attempt: {token[:10]}...")
                return jsonify({"error": "Invalid API token"}), 403
            
            return f(*args, **kwargs)
        
        return decorated_function
    
    def require_auth(f):
        """Decorator to verify user authentication"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            from models import User
            
            auth_header = request.headers.get('Authorization')
            if not auth_header:
                return jsonify({"error": "Missing authorization"}), 401
            
            try:
                token = auth_header.split(" ")[1]
                secret_key = current_app.config.get('SECRET_KEY', 'default_secret')
                decoded = jwt.decode(token, secret_key, algorithms=['HS256'])
                user = User.query.get(decoded['user_id'])
                
                if not user or not user.is_admin:
                    return jsonify({"error": "Admin access required"}), 403
                
                request.user = user
                return f(*args, **kwargs)
            
            except jwt.ExpiredSignatureError:
                return jsonify({"error": "Token expired"}), 401
            except (jwt.InvalidTokenError, IndexError):
                return jsonify({"error": "Invalid token"}), 401
        
        return decorated_function
    
    # ============= BLOCKING ENDPOINTS =============
    
    @blocking_api.route('/block', methods=['POST'])
    @require_api_token
    def block_ip():
        """
        Block an IP address on both Windows and Linux
        
        Accept: JSON with {ip_address, threat_category, risk_score, reason}
        """
        try:
            data = request.get_json()
            
            if not data:
                return jsonify({"error": "Missing request body"}), 400
            
            ip_address = data.get('ip_address')
            threat_category = data.get('threat_category', 'Unknown')
            risk_score = data.get('risk_score', 0)
            reason = data.get('reason', 'Security threat')
            
            # Validate IP
            if not ip_address:
                return jsonify({"error": "Missing ip_address"}), 400
            
            if not _is_valid_ip(ip_address):
                return jsonify({"error": f"Invalid IP address: {ip_address}"}), 400
            
            # Log blocking request
            logger.info(f"API blocking request for {ip_address} from {request.remote_addr}")
            
            threat_info = {
                "category": threat_category,
                "risk_score": risk_score,
                "reason": reason
            }
            
            if not coordinator:
                return jsonify({"error": "Blocking service unavailable"}), 503
            
            result = coordinator.block_threat_ip(
                ip_address=ip_address,
                threat_info=threat_info,
                allow_partial_block=data.get('allow_partial_block', True)
            )
            
            status_code = 200 if result.get("status") in ["completed", "partial"] else 400
            return jsonify(result), status_code
        
        except Exception as e:
            logger.error(f"Error blocking IP: {e}", exc_info=True)
            return jsonify({"error": str(e)}), 500
    
    @blocking_api.route('/unblock', methods=['POST'])
    @require_api_token
    def unblock_ip():
        """
        Unblock an IP address on both Windows and Linux
        
        Accept: JSON with {ip_address}
        """
        try:
            data = request.get_json()
            ip_address = data.get('ip_address')
            
            if not ip_address:
                return jsonify({"error": "Missing ip_address"}), 400
            
            if not _is_valid_ip(ip_address):
                return jsonify({"error": f"Invalid IP address: {ip_address}"}), 400
            
            logger.info(f"API unblocking request for {ip_address} from {request.remote_addr}")
            
            if not coordinator:
                return jsonify({"error": "Blocking service unavailable"}), 503
            
            result = coordinator.unblock_threat_ip(ip_address=ip_address)
            
            status_code = 200 if result.get("status") in ["completed", "partial"] else 400
            return jsonify(result), status_code
        
        except Exception as e:
            logger.error(f"Error unblocking IP: {e}", exc_info=True)
            return jsonify({"error": str(e)}), 500
    
    @blocking_api.route('/status/<ip_address>', methods=['GET'])
    @require_api_token
    def get_blocking_status(ip_address):
        """Get blocking status for a specific IP"""
        try:
            if not _is_valid_ip(ip_address):
                return jsonify({"error": f"Invalid IP address: {ip_address}"}), 400
            
            status = sync_service.get_sync_status(ip_address) if sync_service else None
            
            return jsonify({
                "ip": ip_address,
                "sync_status": status,
                "timestamp": datetime.utcnow().isoformat()
            }), 200
        
        except Exception as e:
            logger.error(f"Error getting status for {ip_address}: {e}")
            return jsonify({"error": str(e)}), 500
    
    # ============= ADMIN AUTHENTICATED ENDPOINTS =============
    
    @blocking_api.route('/list', methods=['GET'])
    @require_auth
    def list_blocked_ips():
        """Get list of all blocked IPs (admin only)"""
        try:
            if not coordinator:
                return jsonify({"error": "Blocking service unavailable"}), 503
            
            blocked_ips = coordinator.get_blocked_ips_list()
            
            return jsonify({
                "count": len(blocked_ips),
                "blocked_ips": blocked_ips,
                "timestamp": datetime.utcnow().isoformat()
            }), 200
        
        except Exception as e:
            logger.error(f"Error listing blocked IPs: {e}", exc_info=True)
            return jsonify({"error": str(e)}), 500
    
    @blocking_api.route('/history/<ip_address>', methods=['GET'])
    @require_auth
    def blocking_history(ip_address):
        """Get blocking history for an IP (admin only)"""
        try:
            if not _is_valid_ip(ip_address):
                return jsonify({"error": f"Invalid IP address: {ip_address}"}), 400
            
            if not coordinator:
                return jsonify({"error": "Blocking service unavailable"}), 503
            
            limit = request.args.get('limit', 10, type=int)
            history = coordinator.get_blocking_history(ip_address, limit=min(limit, 100))
            
            return jsonify({
                "ip": ip_address,
                "history_count": len(history),
                "history": history,
                "timestamp": datetime.utcnow().isoformat()
            }), 200
        
        except Exception as e:
            logger.error(f"Error getting blocking history: {e}")
            return jsonify({"error": str(e)}), 500
    
    @blocking_api.route('/statistics', methods=['GET'])
    @require_auth
    def sync_statistics():
        """Get blocking synchronization statistics (admin only)"""
        try:
            if not coordinator:
                return jsonify({"error": "Blocking service unavailable"}), 503
            
            stats = coordinator.get_sync_statistics()
            
            return jsonify({
                "statistics": stats,
                "timestamp": datetime.utcnow().isoformat()
            }), 200
        
        except Exception as e:
            logger.error(f"Error getting statistics: {e}")
            return jsonify({"error": str(e)}), 500
    
    @blocking_api.route('/health', methods=['GET'])
    def health_check():
        """Check health of blocking systems"""
        try:
            if not coordinator:
                return jsonify({
                    "status": "error",
                    "message": "Blocking service unavailable",
                    "timestamp": datetime.utcnow().isoformat()
                }), 503
            
            health = coordinator.get_system_health()
            
            status_code = 200 if health.get("overall") == "healthy" else 206
            return jsonify({
                **health,
                "timestamp": datetime.utcnow().isoformat()
            }), status_code
        
        except Exception as e:
            logger.error(f"Error checking health: {e}")
            return jsonify({
                "status": "error",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }), 500
    
    @blocking_api.route('/retry/<int:sync_record_id>', methods=['POST'])
    @require_auth
    def retry_sync(sync_record_id):
        """Retry a failed sync (admin only)"""
        try:
            if not coordinator:
                return jsonify({"error": "Blocking service unavailable"}), 503
            
            result = coordinator.retry_failed_sync(sync_record_id)
            
            status_code = 200 if result.get("success") else 400
            return jsonify(result), status_code
        
        except Exception as e:
            logger.error(f"Error retrying sync: {e}")
            return jsonify({"error": str(e)}), 500
    
    @blocking_api.route('/logs', methods=['GET'])
    @require_auth
    def get_sync_logs():
        """Get recent sync logs (admin only)"""
        try:
            from models import SyncLog, db
            
            limit = request.args.get('limit', 50, type=int)
            action_filter = request.args.get('action')
            
            query = SyncLog.query.order_by(SyncLog.timestamp.desc())
            
            if action_filter:
                query = query.filter_by(action=action_filter)
            
            logs = query.limit(min(limit, 500)).all()
            
            return jsonify({
                "count": len(logs),
                "logs": [log.to_dict() for log in logs],
                "timestamp": datetime.utcnow().isoformat()
            }), 200
        
        except Exception as e:
            logger.error(f"Error getting sync logs: {e}")
            return jsonify({"error": str(e)}), 500
    
    @blocking_api.route('/config', methods=['GET'])
    @require_auth
    def get_sync_config():
        """Get sync configuration (admin only)"""
        try:
            from models import SyncConfig
            
            config = SyncConfig.query.first()
            if not config:
                return jsonify({"error": "Sync config not found"}), 404
            
            # Don't expose sensitive data
            safe_config = {
                "linux_host": config.linux_host,
                "linux_port": config.linux_port,
                "linux_api_port": config.linux_api_port,
                "enable_sync": config.enable_sync,
                "auto_retry_failed": config.auto_retry_failed,
                "max_retry_attempts": config.max_retry_attempts,
                "health_check_enabled": config.health_check_enabled,
                "is_healthy": config.is_healthy,
                "block_inbound": config.block_inbound,
                "block_outbound": config.block_outbound,
            }
            
            return jsonify(safe_config), 200
        
        except Exception as e:
            logger.error(f"Error getting sync config: {e}")
            return jsonify({"error": str(e)}), 500
    
    @blocking_api.route('/config', methods=['PUT'])
    @require_auth
    def update_sync_config():
        """Update sync configuration (admin only)"""
        try:
            from models import SyncConfig, db
            
            data = request.get_json()
            
            config = SyncConfig.query.first()
            if not config:
                config = SyncConfig()
                db.session.add(config)
            
            # Update allowed fields
            if 'linux_host' in data:
                config.linux_host = data['linux_host']
            if 'linux_api_port' in data:
                config.linux_api_port = data['linux_api_port']
            if 'enable_sync' in data:
                config.enable_sync = data['enable_sync']
            if 'auto_retry_failed' in data:
                config.auto_retry_failed = data['auto_retry_failed']
            if 'block_inbound' in data:
                config.block_inbound = data['block_inbound']
            if 'block_outbound' in data:
                config.block_outbound = data['block_outbound']
            
            config.updated_at = datetime.utcnow()
            db.session.commit()
            
            logger.info(f"Sync config updated by {request.user.username}")
            
            return jsonify({
                "success": True,
                "message": "Sync config updated",
                "config": config.to_dict()
            }), 200
        
        except Exception as e:
            logger.error(f"Error updating sync config: {e}")
            return jsonify({"error": str(e)}), 500
    
    @blocking_api.route('/verify-connectivity', methods=['GET'])
    @require_auth
    def verify_connectivity():
        """Verify connectivity between Windows and Linux systems"""
        try:
            import requests
            from models import SyncConfig
            
            config = SyncConfig.query.first()
            if not config:
                return jsonify({"error": "Sync config not found"}), 404
            
            # Test Windows
            windows_test = {
                "status": "checking",
                "result": None
            }
            try:
                import subprocess
                result = subprocess.run(
                    "netsh advfirewall show allprofiles",
                    shell=True,
                    capture_output=True,
                    timeout=5,
                    text=True
                )
                windows_test["status"] = "healthy" if result.returncode == 0 else "unhealthy"
                windows_test["result"] = result.returncode == 0
            except Exception as e:
                windows_test["status"] = "error"
                windows_test["error"] = str(e)
            
            # Test Linux
            linux_test = {
                "status": "checking",
                "result": None
            }
            try:
                url = f"http://{config.linux_host}:{config.linux_api_port}/api/health"
                response = requests.get(url, timeout=5)
                linux_test["status"] = "healthy" if response.status_code == 200 else "unhealthy"
                linux_test["result"] = response.status_code == 200
            except requests.exceptions.Timeout:
                linux_test["status"] = "timeout"
                linux_test["error"] = "Request timeout"
            except requests.exceptions.ConnectionError:
                linux_test["status"] = "unreachable"
                linux_test["error"] = "Cannot connect"
            except Exception as e:
                linux_test["status"] = "error"
                linux_test["error"] = str(e)
            
            overall_status = "healthy" if (
                windows_test["status"] == "healthy" and 
                linux_test["status"] == "healthy"
            ) else "degraded"
            
            return jsonify({
                "overall_status": overall_status,
                "windows": windows_test,
                "linux": linux_test,
                "timestamp": datetime.utcnow().isoformat()
            }), 200
        
        except Exception as e:
            logger.error(f"Error verifying connectivity: {e}")
            return jsonify({"error": str(e)}), 500
    
    return blocking_api


def _is_valid_ip(ip_address: str) -> bool:
    """Validate IP address (IPv4 or IPv6)"""
    import re
    
    # IPv4 validation
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ipv4_pattern, ip_address):
        try:
            parts = ip_address.split('.')
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False
    
    # IPv6 validation (simplified)
    ipv6_pattern = r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$'
    return bool(re.match(ipv6_pattern, ip_address))
