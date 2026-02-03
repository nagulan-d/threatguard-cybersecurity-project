from app import app, db, User

with app.app_context():
    # Check existing users
    print("Checking existing users...")
    users = User.query.all()
    print(f"Total users: {len(users)}")
    for u in users:
        print(f"  - {u.username} (role: {u.role}, sub: {u.subscription})")

    # Create admin if doesn't exist
    admin = User.query.filter_by(username="admin").first()
    if not admin:
        print("\nCreating admin user...")
        admin = User(
            username="admin",
            email="admin@threatguard.com",
            phone="+1 (555) 000-0000",
            role="admin",
            subscription="premium"
        )
        admin.set_password("admin123")
        db.session.add(admin)
        db.session.commit()
        print("✅ Admin user created!")
    else:
        print(f"\n✅ Admin user already exists!")

    # Verify
    admin_check = User.query.filter_by(username="admin").first()
    print(f"\nVerification:")
    print(f"  Username: {admin_check.username}")
    print(f"  Role: {admin_check.role}")
    print(f"  Subscription: {admin_check.subscription}")
    print(f"  Email: {admin_check.email}")

