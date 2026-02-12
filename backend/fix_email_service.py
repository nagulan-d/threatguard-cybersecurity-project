"""
Script to fix block_url None handling in email_service.py
"""
with open('email_service.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Replace the concatenation to handle None
content = content.replace(
    '\' + block_url + \'',
    '\' + (block_url or \'#\') + \''
)

# Add block_url check to the condition
content = content.replace(
    'if is_subscribed and has_ip else',
    'if (is_subscribed and has_ip and block_url) else'
)

# Make block_url optional in send_threat_notification_email
content = content.replace(
    'block_url: str,\n    unsubscribe_url: str,',
    'block_url: str = None,\n    unsubscribe_url: str = "",',
    1  # Only first occurrence (in send_threat_notification_email function)
)

# Fix the text_body action_info to handle None block_url
old_action = '''        if is_premium and has_ip:
            action_info = f"\\nTo block this threat, visit: {block_url}"'''
new_action = '''        if is_premium and has_ip:
            action_info = f"\\nTo block this threat, visit: {block_url}" if block_url else "\\nView details in your dashboard."'''

content = content.replace(old_action, new_action)

with open('email_service.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("✅ Fixed email_service.py")
print("   - Made block_url parameter optional") 
print("   - Added None handling for block_url concatenation")
print("   - Updated condition to check block_url exists")
