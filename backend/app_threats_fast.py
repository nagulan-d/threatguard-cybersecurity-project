# FAST VERSION - Replace the @app.route("/api/threats") function with this

@app.route("/api/threats", methods=["GET"])
def get_threats():
    """Fast version - returns randomized cached threats instantly."""
    print("\n🚀 /api/threats called")
    
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
