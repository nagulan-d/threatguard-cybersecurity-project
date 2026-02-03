from app import app, mail
from flask_mail import Message
import os

recipient = os.getenv('MAIL_USERNAME') or 'youremail@example.com'

with app.app_context():
    msg = Message(subject="ThreatGuard – Test Email",
                  recipients=[recipient])
    msg.body = "This is a test message from ThreatGuard backend.\nIf this fails, the exception will be printed."
    try:
        mail.send(msg)
        print("Email sent successfully to", recipient)
    except Exception as e:
        # Print repr to capture full exception details without exposing secrets
        print("Email send error:", repr(e))
