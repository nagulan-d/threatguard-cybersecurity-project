# Fix the broken app.py file
with open("app.py", "r", encoding="utf-8") as f:
    content = f.read()

# Fix the broken print statement
content = content.replace('print("\n🚀 /api/threats called")', 'print("\\n🚀 /api/threats called")')

with open("app.py", "w", encoding="utf-8") as f:
    f.write(content)

print("✅ Fixed print statement")
