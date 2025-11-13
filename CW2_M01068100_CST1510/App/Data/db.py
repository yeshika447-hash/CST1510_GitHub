import sqlite3
from pathlib import Path

DB_PATH =Path("DATA") / "intelligence_platform.db"

def connect_database(db_path=DB_PATH):
    db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(db_path))
    print(f"Connected to database at: {db_path}")
    return sqlite3.connect(str(db_path))
