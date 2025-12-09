"""
State management for checkpoint/resume functionality
"""

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional, Any, Dict

from loguru import logger


class StateManager:
    """Manages assessment state for checkpoint/resume"""
    
    def __init__(self, db_path: str):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
    
    def _init_db(self):
        """Initialize the state database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS checkpoints (
                stage_name TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                data TEXT NOT NULL
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                stage TEXT NOT NULL,
                action TEXT NOT NULL,
                details TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def save_checkpoint(self, stage_name: str, data: Any):
        """Save a checkpoint for a stage"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Serialize data
            serialized = json.dumps(data, default=str)
            timestamp = datetime.now().isoformat()
            
            cursor.execute('''
                INSERT OR REPLACE INTO checkpoints (stage_name, timestamp, data)
                VALUES (?, ?, ?)
            ''', (stage_name, timestamp, serialized))
            
            conn.commit()
            conn.close()
            
            logger.debug(f"Checkpoint saved for stage: {stage_name}")
            
        except Exception as e:
            logger.error(f"Failed to save checkpoint: {e}")
    
    def load_checkpoint(self, stage_name: str) -> Optional[Dict]:
        """Load a checkpoint for a stage"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT data FROM checkpoints WHERE stage_name = ?
            ''', (stage_name,))
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return json.loads(row[0])
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to load checkpoint: {e}")
            return None
    
    def clear_checkpoints(self):
        """Clear all checkpoints"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('DELETE FROM checkpoints')
            conn.commit()
            conn.close()
            logger.info("All checkpoints cleared")
        except Exception as e:
            logger.error(f"Failed to clear checkpoints: {e}")
    
    def log_action(self, stage: str, action: str, details: Optional[str] = None):
        """Log an action to the audit log"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            timestamp = datetime.now().isoformat()
            
            cursor.execute('''
                INSERT INTO audit_log (timestamp, stage, action, details)
                VALUES (?, ?, ?, ?)
            ''', (timestamp, stage, action, details))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Failed to log action: {e}")
    
    def get_audit_log(self, stage: Optional[str] = None) -> list:
        """Retrieve audit log entries"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            if stage:
                cursor.execute('''
                    SELECT timestamp, stage, action, details
                    FROM audit_log
                    WHERE stage = ?
                    ORDER BY timestamp DESC
                ''', (stage,))
            else:
                cursor.execute('''
                    SELECT timestamp, stage, action, details
                    FROM audit_log
                    ORDER BY timestamp DESC
                ''')
            
            rows = cursor.fetchall()
            conn.close()
            
            return [
                {
                    'timestamp': row[0],
                    'stage': row[1],
                    'action': row[2],
                    'details': row[3]
                }
                for row in rows
            ]
            
        except Exception as e:
            logger.error(f"Failed to retrieve audit log: {e}")
            return []
