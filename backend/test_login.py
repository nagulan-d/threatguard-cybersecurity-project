from app import app, db, User

with app.app_context():
    admin = User.query.filter_by(username='admin').first()
    print(f'Admin exists: {admin is not None}')
    if admin:
        print(f'Admin username: {admin.username}')
        print(f'Password check admin123: {admin.check_password("admin123")}')
        print(f'Password check admin: {admin.check_password("admin")}')
    
    rocky = User.query.filter_by(username='Rocky').first()
    if rocky:
        print(f'\nRocky username: {rocky.username}')
        print(f'Password check 123456: {rocky.check_password("123456")}')
