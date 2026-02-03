#!/usr/bin/env python3
"""Check SQLAlchemy model for UNIQUE constraint."""

import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from app import app, BlockedThreat
from sqlalchemy.schema import CreateTable

try:
    with app.app_context():
        # Get the CREATE TABLE statement
        create_table_stmt = CreateTable(BlockedThreat.__table__)
        print("[SQLAlchemy Model Definition]")
        print(str(create_table_stmt.compile(compile_kwargs={"literal_binds": True})))
        
        # Check for constraints
        print("\n[Constraints]")
        for constraint in BlockedThreat.__table__.constraints:
            print(f"  {type(constraint).__name__}: {constraint}")
        
        # Check for indexes
        print("\n[Indexes]")
        for index in BlockedThreat.__table__.indexes:
            print(f"  {index.name}: {index}")
            print(f"    Unique: {index.unique}")
            print(f"    Columns: {[c.name for c in index.columns]}")
        
except Exception as e:
    print(f"[ERROR] {e}")
    import traceback
    traceback.print_exc()
