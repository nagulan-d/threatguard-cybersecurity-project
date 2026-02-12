from app import app, db, User

with app.app_context():
    print("User table columns:")
    for column in User.__table__.columns:
        print(f"  - {column.name}: {column.type}")
    
    user = User.query.first()
    if user:
        print(f"\nFirst user: {user.username}")
        print(f"Has is_premium: {hasattr(user, 'is_premium')}")
        if hasattr(user, 'is_premium'):
            print(f"is_premium value: {user.is_premium}")
    else:
        print("\nNo users found")
