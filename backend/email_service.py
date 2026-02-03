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
    block_url: str,
    unsubscribe_url: str
) -> str:
    """
    Generate HTML email template for high-risk threat notification.
    Supports BRIEF (free users) and EXPANDED (premium users) formats.
    
    Args:
        user_name: Recipient's name
        threat_data: Threat information including IP, type, score, summary, notification_type
        block_url: URL for "Block IP" button action
        unsubscribe_url: URL to unsubscribe from notifications
    
    Returns:
        HTML email content
    """
    ip_address = threat_data.get('ip_address', 'Unknown')
    threat_type = threat_data.get('threat_type', 'Unknown')
    risk_score = threat_data.get('risk_score', 0)
    summary = threat_data.get('summary', 'Block or monitor this IP')
    notification_type = threat_data.get('notification_type', 'brief')
    
    # Color coding based on risk (High: >=75 Red, Medium: 50-74 Yellow, Low: <50 Green)
    if risk_score >= 75:
        risk_color = '#dc3545'
        risk_label = 'HIGH'
    elif risk_score >= 50:
        risk_color = '#ffc107'
        risk_label = 'MEDIUM'
    else:
        risk_color = '#28a745'
        risk_label = 'LOW'
    
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
                                        <p style="margin:0 0 8px 0; font-size:13px; font-weight:600; color:#17a2b8;">🛡️ PREMIUM: Detailed Prevention Guide</p>
                                        
                                        <p style="margin:0 0 8px 0; font-size:12px;"><strong>Category:</strong> {category}</p>
                                        <p style="margin:0 0 8px 0; font-size:12px;"><strong>Prevention Strategy:</strong></p>
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
                                    <strong>⭐ Upgrade to Premium</strong> for detailed prevention guides, priority alerts, and advanced threat analytics.
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
                            <h2 style="color:#ffffff; margin:0; font-size:20px;">Threat Detected</h2>
                            <p style="color:#f0f0f0; margin:5px 0 0 0; font-size:13px;">Risk Level: {risk_label}</p>
                        </td>
                    </tr>
                    
                    <!-- Body -->
                    <tr>
                        <td style="padding:25px;">
                            <p style="margin:0 0 15px 0; font-size:14px; color:#333;">Hello {user_name},</p>
                            
                            <!-- Threat Info -->
                            <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#f8f9fa; border-left:4px solid {risk_color}; margin:15px 0;">
                                <tr>
                                    <td style="padding:15px;">
                                        <p style="margin:0 0 8px 0; font-size:13px;"><strong>IP Address:</strong></p>
                                        <p style="margin:0 0 12px 0; font-size:14px; font-family:monospace; color:#333;">{ip_address}</p>
                                        
                                        <p style="margin:0 0 8px 0; font-size:13px;"><strong>Threat Type:</strong></p>
                                        <p style="margin:0 0 12px 0; font-size:14px; color:#333;">{threat_type}</p>
                                        
                                        <p style="margin:0 0 8px 0; font-size:13px;"><strong>Risk Score:</strong></p>
                                        <p style="margin:0 0 12px 0; font-size:14px; color:#333;">{risk_score}/100</p>
                                        
                                        <p style="margin:0 0 8px 0; font-size:13px;"><strong>Summary:</strong></p>
                                        <p style="margin:0; font-size:14px; color:#333; line-height:1.5;">{summary}</p>
                                    </td>
                                </tr>
                            </table>
                            
                            {expanded_section}
                            
                            <!-- Block Button -->
                            <div style="text-align:center; margin:25px 0;">
                                <a href="{block_url}" style="display:inline-block; padding:14px 32px; background-color:{risk_color}; color:#ffffff; text-decoration:none; border-radius:6px; font-size:15px; font-weight:600; box-shadow:0 2px 6px rgba(0,0,0,0.2);">
                                    Block This IP
                                </a>
                            </div>
                            
                            <p style="margin:15px 0; font-size:12px; color:#666; line-height:1.6;">
                                <em>Click the button above to block {ip_address} on your environment. This action is instant and cannot be undone here - manage it in your dashboard.</em>
                            </p>
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
                            <h2 style="color:#ffffff; margin:0; font-size:20px;">IP Successfully Blocked</h2>
                            <p style="color:#f0f0f0; margin:5px 0 0 0; font-size:13px;">Your environment is now protected</p>
                        </td>
                    </tr>
                    
                    <!-- Body -->
                    <tr>
                        <td style="padding:25px;">
                            <p style="margin:0 0 15px 0; font-size:14px; color:#333;">Hello {user_name},</p>
                            
                            <!-- Success Message -->
                            <div style="background-color:#d4edda; border-left:4px solid #28a745; padding:15px; margin:15px 0; border-radius:4px;">
                                <p style="margin:0 0 10px 0; font-size:13px; font-weight:600; color:#155724;">IP Address Blocked:</p>
                                <p style="margin:0 0 8px 0; font-size:16px; font-family:monospace; color:#000; font-weight:600;">{ip_address}</p>
                                <p style="margin:0 0 5px 0; font-size:13px; color:#155724;"><strong>Type:</strong> {threat_type}</p>
                                <p style="margin:0; font-size:13px; color:#155724;"><strong>Blocked:</strong> {blocked_at}</p>
                            </div>
                            
                            <p style="margin:15px 0; font-size:14px; color:#333; line-height:1.6;">
                                This IP is now blocked and cannot access your environment. You can manage it anytime from your dashboard.
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
    block_url: str,
    unsubscribe_url: str
) -> bool:
    """
    Send threat notification email with "Block IP" button.
    
    Args:
        mail: Flask-Mail instance
        recipient_email: Recipient's email address
        recipient_name: Recipient's name
        threat_data: Complete threat information
        block_url: URL for blocking action
        unsubscribe_url: URL to unsubscribe
    
    Returns:
        True if email sent successfully, False otherwise
    """
    try:
        subject = f"🚨 High-Risk Threat Alert: {threat_data.get('ip_address', 'Unknown IP')}"
        
        html_body = get_threat_email_template(
            user_name=recipient_name,
            threat_data=threat_data,
            block_url=block_url,
            unsubscribe_url=unsubscribe_url
        )
        
        # Plain text fallback
        text_body = f"""
High-Risk Threat Detected

Hello {recipient_name},

We've detected a high-risk threat targeting your protected environment.

Threat Details:
- IP Address: {threat_data.get('ip_address', 'Unknown')}
- Threat Type: {threat_data.get('threat_type', 'Unknown')}
- Risk Score: {threat_data.get('risk_score', 0)}/100
- Risk Category: {threat_data.get('risk_category', 'High')}
- Summary: {threat_data.get('summary', 'No description')}

To block this IP address, visit: {block_url}

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
        subject = f"[CONFIRMED] IP {ip_address} Successfully Blocked"
        
        html_body = get_confirmation_email_template(
            user_name=recipient_name,
            ip_address=ip_address,
            threat_type=threat_type,
            blocked_at=blocked_at
        )
        
        # Plain text fallback
        text_body = f"""
IP Successfully Blocked

Hello {recipient_name},

Great news! The malicious IP address has been successfully blocked on your protected environment.

Blocked IP Details:
- IP Address: {ip_address}
- Threat Type: {threat_type}
- Blocked At: {blocked_at}

This IP address is now actively blocked and cannot access your environment.

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
