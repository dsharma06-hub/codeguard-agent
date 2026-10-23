# Clean Python database service using parameterized queries
import sqlite3
from typing import Optional, Dict, Any

class UserService:
    def __init__(self, db_path: str = "app.db"):
        self.db_path = db_path

    def get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        # Safe parameterized SQL query with bound placeholder
        query = "SELECT id, email, role FROM users WHERE id = ?"
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(query, (user_id,))
            row = cursor.fetchone()
            if row:
                return {"id": row[0], "email": row[1], "role": row[2]}
        return None
