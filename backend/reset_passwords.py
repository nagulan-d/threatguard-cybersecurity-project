from app import app, db, User

with app.app_context():
    # Re-hash all existing user passwords
    users = User.query.all()
    
    # Define passwords for each user
    passwords = {
        'admin': 'admin123',
        'mohan': '123456',
        'mohandas': '123456',
        'Rocky': '123456',
        'CTI': '123456'
    }
    
    for user in users:
        if user.username in passwords:
            user.set_password(passwords[user.username])
            print(f"✅ Updated {user.username} password")
    
    db.session.commit()
    print("\n✅ All passwords updated successfully!")
    
    # Verify
    print("\nVerification:")
    for user in User.query.all():
        pwd = passwords.get(user.username, 'unknown')
        is_valid = user.check_password(pwd)
        print(f"  {user.username}: {pwd} -> {is_valid}")
