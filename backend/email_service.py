"""
Email notification service for Cyber Threat Intelligence platform.
Sends HTML emails with "Block IP" action buttons for high-risk threats.
"""

from flask_mail import Message
from datetime import datetime
import secrets
import json
from typing import Dict, Any, Optional


def generate_block_token(user_id: int, ip_address: str, threat_data: Dict[str, Any]) -> str:
    """
    Generate a secure one-time token for IP blocking action.
    
    Args:
        user_id: User ID who will receive the email
        ip_address: IP address to be blocked
        threat_data: Complete threat information
    
    Returns:
        Secure token string
    """
    token_data = {
        'user_id': user_id,
        'ip_address': ip_address,
        'threat_type': threat_data.get('threat_type', 'Unknown'),
        'risk_score': threat_data.get('risk_score', 0),
        'timestamp': datetime.utcnow().isoformat(),
        'nonce': secrets.token_urlsafe(16)
    }
    
    # Encode token (in production, use JWT or encrypted tokens)
    token = secrets.token_urlsafe(32)
    return token


def get_threat_email_template(
    user_name: str,
    threat_data: Dict[str, Any],
    block_url: str = None,
    unsubscribe_url: str = "",
    is_subscribed: bool = True
) -> str:
    """
    Generate HTML email template for high-risk threat notification.
    Supports BRIEF (free users) and EXPANDED (premium users) formats.
    Simple format for non-subscribers.
    
    Args:
        user_name: Recipient's name
        threat_data: Threat information including IP, type, score, summary, notification_type
        block_url: URL for blocking action (only shown if subscribed and IP exists)
        unsubscribe_url: URL to unsubscribe from notifications
        is_subscribed: Whether user has active subscription
    
    Returns:
        HTML email content
    """
    ip_address = threat_data.get('ip_address', 'Unknown')
    threat_type = threat_data.get('threat_type', 'Unknown')
    risk_score = threat_data.get('risk_score', 0)
    summary = threat_data.get('summary', 'Review this activity in your dashboard')
    notification_type = threat_data.get('notification_type', 'brief')
    has_ip = ip_address and ip_address != 'Unknown' and ip_address != 'N/A'
    
    # Color coding based on risk (High: >=75 Red, Medium: 50-74 Yellow, Low: <50 Green)
    if risk_score >= 75:
        risk_color = '#dc3545'  # Red for high risk
        risk_label = 'HIGH'
    elif risk_score >= 50:
        risk_color = '#ffc107'  # Yellow for medium
        risk_label = 'MEDIUM'
    else:
        risk_color = '#28a745'  # Green for low
        risk_label = 'LOW'
    
    # Obfuscate IP address to avoid spam filters
    if has_ip:
        ip_parts = str(ip_address).split('.')
        if len(ip_parts) == 4:
            ip_display = f"{ip_parts[0]}.{ip_parts[1]}.xxx.xxx"
        else:
            ip_display = "Address (view in dashboard)"
    else:
        ip_display = "No IP Address" if 'domain' in threat_type.lower() or 'url' in threat_type.lower() else "N/A"
    
    # Expanded content for premium users
    expanded_section = ''
    if notification_type == 'expanded':
        prevention = threat_data.get('prevention', '')
        prevention_steps = threat_data.get('prevention_steps', '')
        category = threat_data.get('category', 'Unknown')
        
        expanded_section = f"""
                            <!-- PREMIUM: Expanded Details -->
                            <table width="100%" cellpadding="0" cellspacing="0" style="margin:15px 0;">
                                <tr>
                                    <td style="padding:15px; background-color:#e8f4f8; border-left:3px solid #17a2b8; border-radius:4px;">
                                        <p style="margin:0 0 8px 0; font-size:13px; font-weight:600; color:#17a2b8;">PREMIUM: Detailed Analysis</p>
                                        
                                        <p style="margin:0 0 8px 0; font-size:12px;"><strong>Category:</strong> {category}</p>
                                        <p style="margin:0 0 8px 0; font-size:12px;"><strong>Mitigation Strategy:</strong></p>
                                        <p style="margin:0 0 12px 0; font-size:12px; color:#333; line-height:1.5;">{prevention}</p>
                                        
                                        {f'<p style="margin:0 0 8px 0; font-size:12px;"><strong>Action Steps:</strong></p><p style="margin:0; font-size:12px; color:#333; line-height:1.6; white-space:pre-line;">{prevention_steps}</p>' if prevention_steps else ''}
                                    </td>
                                </tr>
                            </table>
"""
    else:
        # Brief version for free users
        expanded_section = """
                            <!-- FREE: Upgrade Prompt -->
                            <div style="padding:12px; background-color:#fff3cd; border-left:3px solid #ffc107; border-radius:4px; margin:15px 0;">
                                <p style="margin:0; font-size:12px; color:#856404; line-height:1.5;">
                                    <strong>Upgrade to Premium</strong> for detailed analysis, priority alerts, and advanced analytics.
                                </p>
                            </div>
"""
    
    html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin:0; padding:0; font-family:Arial, sans-serif; background-color:#f5f5f5;">
    <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#f5f5f5;">
        <tr>
            <td align="center" style="padding:20px 0;">
                <table width="550" cellpadding="0" cellspacing="0" style="background-color:#ffffff; border-radius:8px; box-shadow:0 2px 8px rgba(0,0,0,0.1);">
                    
                    <!-- Header -->
                    <tr>
                        <td style="background:linear-gradient(135deg, {risk_color} 0%, {risk_color}dd 100%); padding:25px; text-align:center; border-radius:8px 8px 0 0;">
                            <h2 style="color:#ffffff; margin:0; font-size:20px;">Security Activity Alert</h2>
                            <p style="color:#f0f0f0; margin:5px 0 0 0; font-size:13px;">Priority Level: {risk_label}</p>
                        </td>
                    </tr>
                    
                    <!-- Body -->
                    <tr>
                        <td style="padding:25px;">
                            <p style="margin:0 0 15px 0; font-size:14px; color:#333;">Hello {user_name},</p>
                            
                            <!-- Activity Info -->
                            <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#f8f9fa; border-left:4px solid {risk_color}; margin:15px 0;">
                                <tr>
                                    <td style="padding:15px;">
                                        {f'<p style="margin:0 0 8px 0; font-size:13px;"><strong>Source:</strong></p><p style="margin:0 0 12px 0; font-size:14px; font-family:monospace; color:#333;">{ip_display}</p>' if has_ip else ''}
                                        
                                        <p style="margin:0 0 8px 0; font-size:13px;"><strong>Type:</strong></p>
                                        <p style="margin:0 0 12px 0; font-size:14px; color:#333;">{threat_type}</p>
                                        
                                        <p style="margin:0 0 8px 0; font-size:13px;"><strong>Score:</strong></p>
                                        <p style="margin:0 0 12px 0; font-size:14px; color:#333;">{risk_score}/100</p>
                                        
                                        <p style="margin:0 0 8px 0; font-size:13px;"><strong>Details:</strong></p>
                                        <p style="margin:0; font-size:14px; color:#333; line-height:1.5;">{summary}</p>
                                    </td>
                                </tr>
                            </table>
                            
                            {expanded_section}
                            
                            {'<!-- Action Button for Premium + IP -->\n                            <div style="text-align:center; margin:25px 0;">\n                                <a href="' + (block_url or '#') + '" style="display:inline-block; padding:14px 32px; background-color:' + risk_color + '; color:#ffffff; text-decoration:none; border-radius:6px; font-size:15px; font-weight:600; box-shadow:0 2px 6px rgba(0,0,0,0.2);">\n                                    Block This Threat\n                                </a>\n                            </div>\n                            <p style="margin:15px 0; font-size:12px; color:#666; line-height:1.6; text-align:center;">\n                                <em>Click above to block and protect your environment.</em>\n                            </p>' if (is_subscribed and has_ip and block_url) else ('<p style="margin:15px 0; font-size:13px; color:#666; text-align:center; background:#f0f0f0; padding:12px; border-radius:4px;">\n                                View full details in your <strong>Dashboard</strong>.' + (' Upgrade to <strong>Premium</strong> for instant blocking controls.' if not is_subscribed else '') + '\n                            </p>')}
                        </td>
                    </tr>
                    
                    <!-- Footer -->
                    <tr>
                        <td style="padding:15px; background-color:#f8f9fa; text-align:center; border-top:1px solid #ddd; border-radius:0 0 8px 8px;">
                            <p style="margin:0; font-size:12px; color:#999;">
                                <a href="{unsubscribe_url}" style="color:#667eea; text-decoration:none;">Unsubscribe</a> | 
                                CTI Platform
                            </p>
                        </td>
                    </tr>
                    
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
    """
    
    return html.strip()


def get_confirmation_email_template(
    user_name: str,
    ip_address: str,
    threat_type: str,
    blocked_at: str
) -> str:
    """Generate HTML email for successful IP block confirmation."""
    # Obfuscate IP to avoid spam filters
    ip_parts = ip_address.split('.')
    if len(ip_parts) == 4:
        ip_display = f"{ip_parts[0]}.{ip_parts[1]}.xxx.xxx"
    else:
        ip_display = "Network Address"
    
    html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin:0; padding:0; font-family:Arial, sans-serif; background-color:#f5f5f5;">
    <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#f5f5f5;">
        <tr>
            <td align="center" style="padding:20px 0;">
                <table width="550" cellpadding="0" cellspacing="0" style="background-color:#ffffff; border-radius:8px; box-shadow:0 2px 8px rgba(0,0,0,0.1);">
                    
                    <!-- Header -->
                    <tr>
                        <td style="background:linear-gradient(135deg, #28a745 0%, #20c997 100%); padding:25px; text-align:center; border-radius:8px 8px 0 0;">
                            <h2 style="color:#ffffff; margin:0; font-size:20px;">Action Completed Successfully</h2>
                            <p style="color:#f0f0f0; margin:5px 0 0 0; font-size:13px;">Network protection has been updated</p>
                        </td>
                    </tr>
                    
                    <!-- Body -->
                    <tr>
                        <td style="padding:25px;">
                            <p style="margin:0 0 15px 0; font-size:14px; color:#333;">Hello {user_name},</p>
                            
                            <!-- Success Message -->
                            <div style="background-color:#d4edda; border-left:4px solid #28a745; padding:15px; margin:15px 0; border-radius:4px;">
                                <p style="margin:0 0 10px 0; font-size:13px; font-weight:600; color:#155724;">Action Completed:</p>
                                <p style="margin:0 0 8px 0; font-size:16px; font-family:monospace; color:#000; font-weight:600;">{ip_display}</p>
                                <p style="margin:0 0 5px 0; font-size:13px; color:#155724;"><strong>Type:</strong> {threat_type}</p>
                                <p style="margin:0; font-size:13px; color:#155724;"><strong>Timestamp:</strong> {blocked_at}</p>
                            </div>
                            
                            <p style="margin:15px 0; font-size:14px; color:#333; line-height:1.6;">
                                This address has been processed and your network protection updated. You can manage settings from your dashboard.
                            </p>
                        </td>
                    </tr>
                    
                    <!-- Footer -->
                    <tr>
                        <td style="padding:15px; background-color:#f8f9fa; text-align:center; border-top:1px solid #ddd; border-radius:0 0 8px 8px;">
                            <p style="margin:0; font-size:12px; color:#999;">CTI Platform - Automated Confirmation</p>
                        </td>
                    </tr>
                    
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
    """
    return html.strip()


def send_threat_notification_email(
    mail,
    recipient_email: str,
    recipient_name: str,
    threat_data: Dict[str, Any],
    block_url: str = None,
    unsubscribe_url: str = "",
    is_premium: bool = False
) -> bool:
    """
    Send threat notification email.
    Shows action button only for PREMIUM users with IP-based threats.
    
    Args:
        mail: Flask-Mail instance
        recipient_email: Recipient's email address
        recipient_name: Recipient's name
        threat_data: Complete threat information
        block_url: URL for blocking action
        unsubscribe_url: URL to unsubscribe
        is_premium: Whether user has premium subscription (for blocking)
    
    Returns:
        True if email sent successfully, False otherwise
    """
    try:
        # Sanitize subject to avoid Gmail security filters
        risk_score = threat_data.get('risk_score', 0)
        threat_type = threat_data.get('threat_type', 'Activity')
        subject = f"Security Alert - Priority {risk_score} - {threat_type[:20]}"
        
        # Determine if blocking button should be shown (premium + has IP)
        ip_val = threat_data.get('ip_address', 'N/A')
        has_ip = ip_val and ip_val not in ['N/A', 'Unknown', '']
        show_blocking = is_premium and has_ip
        
        html_body = get_threat_email_template(
            user_name=recipient_name,
            threat_data=threat_data,
            block_url=block_url,
            unsubscribe_url=unsubscribe_url,
            is_subscribed=show_blocking  # Only show block button if premium with IP
        )
        
        # Plain text fallback - sanitized to avoid spam filters
        ip_info = f"- Source: {threat_data.get('ip_address', 'N/A')}\n" if has_ip else ""
        
        if is_premium and has_ip:
            action_info = f"\nTo block this threat, visit: {block_url}" if block_url else "\nView details in your dashboard." if block_url else "\nView details in your dashboard."
        elif is_premium:
            action_info = "\nView details in your dashboard."
        else:
            action_info = "\nUpgrade to Premium for instant blocking controls."
        
        text_body = f"""
Security Activity Alert

Hello {recipient_name},

A security activity requires your attention.

Details:
{ip_info}- Type: {threat_data.get('threat_type', 'Unknown')}
- Priority: {threat_data.get('risk_score', 0)}/100
- Info: {threat_data.get('summary', 'Review recommended')}
{action_info}

This is an automated threat notification from your CTI Platform.
        """
        
        msg = Message(
            subject=subject,
            recipients=[recipient_email],
            body=text_body,
            html=html_body
        )
        
        mail.send(msg)
        print(f"[SUCCESS] Threat notification email sent to {recipient_email}")
        return True
        
    except Exception as e:
        print(f"[ERROR] Failed to send threat notification email to {recipient_email}: {str(e)}")
        return False


def send_confirmation_email(
    mail,
    recipient_email: str,
    recipient_name: str,
    ip_address: str,
    threat_type: str,
    blocked_at: str
) -> bool:
    """
    Send confirmation email after successful IP block.
    
    Args:
        mail: Flask-Mail instance
        recipient_email: Recipient's email address
        recipient_name: Recipient's name
        ip_address: Blocked IP address
        threat_type: Type of threat
        blocked_at: Timestamp when blocked
    
    Returns:
        True if email sent successfully, False otherwise
    """
    try:
        # Sanitize subject to avoid spam filters
        ip_parts = ip_address.split('.')
        if len(ip_parts) == 4:
            ip_masked = f"{ip_parts[0]}.{ip_parts[1]}.xxx.xxx"
        else:
            ip_masked = "Address"
        subject = f"Action Confirmed - Network Protection Updated ({ip_masked})"
        
        html_body = get_confirmation_email_template(
            user_name=recipient_name,
            ip_address=ip_address,
            threat_type=threat_type,
            blocked_at=blocked_at
        )
        
        # Plain text fallback
        text_body = f"""
Action Completed Successfully

Hello {recipient_name},

Your network protection has been successfully updated.

Details:
- Address: {ip_address}
- Activity Type: {threat_type}
- Timestamp: {blocked_at}

This address has been processed and your network protection updated accordingly.

© {datetime.utcnow().year} Cyber Threat Intelligence Platform
        """
        
        msg = Message(
            subject=subject,
            recipients=[recipient_email],
            body=text_body,
            html=html_body
        )
        
        mail.send(msg)
        print(f"[SUCCESS] Confirmation email sent to {recipient_email}")
        return True
        
    except Exception as e:
        print(f"[ERROR] Failed to send confirmation email to {recipient_email}: {str(e)}")
        return False
