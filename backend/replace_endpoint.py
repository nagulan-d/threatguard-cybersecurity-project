import re

# Read the current app.py
with open("app.py", "r", encoding="utf-8") as f:
    content = f.read()

# Define the new fast function
new_function = '''@app.route("/api/threats", methods=["GET"])
def get_threats():
    """Fast version - returns randomized cached threats instantly."""
    print("\\n🚀 /api/threats called")
    
    try:
        limit = int(request.args.get("limit", 15))
    except Exception:
        limit = 15
    
    # Load and randomize cached threats
    try:
        with open(THREATS_OUTPUT, "r", encoding="utf-8") as f:
            all_threats = json.load(f)
        
        # Randomize
        random.shuffle(all_threats)
        
        # Apply category filter if requested
        category = request.args.get("category")
        if category and category != "All":
            all_threats = [t for t in all_threats if t.get("category") == category]
        
        # Return requested limit
        threats = all_threats[:limit]
        
        print(f"✅ Returning {len(threats)} randomized threats")
        return jsonify(threats)
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return jsonify([])
'''

# Find and replace the old function (from @app.route("/api/threats") to the next @app.route)
pattern = r'@app\.route\("/api/threats", methods=\["GET"\]\).*?(?=@app\.route\("/api/admin-alerts")'
replacement = new_function + '\n'

new_content = re.sub(pattern, replacement, content, flags=re.DOTALL)

# Write back
with open("app.py", "w", encoding="utf-8") as f:
    f.write(new_content)

print("✅ Replaced /api/threats endpoint with fast version")
