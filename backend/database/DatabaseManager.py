import sqlite3
import os
from datetime import datetime
from typing import List, Dict, Any, Optional

class DatabaseManager:
    """
    Singleton class for handling all SQLite database interactions.
    
    This class manages the database connection, schema initialization, 
    and provides methods for logging alerts, flow statistics, and system events.
    It ensures thread-safety for SQLite connections by using a Singleton pattern
    and configuring the connection appropriately.
    """
    _instance: Optional['DatabaseManager'] = None

    def __new__(cls, *args: Any, **kwargs: Any) -> 'DatabaseManager':
        """
        Singleton Pattern: Ensures only one instance of the DatabaseManager exists.
        
        Returns:
            DatabaseManager: The singleton instance.
        """
        if not cls._instance:
            cls._instance = super(DatabaseManager, cls).__new__(cls)
        return cls._instance

    def __init__(self, db_path: str = "ids_logs.db") -> None:
        """
        Initializes the database connection and creates tables if they don't exist.
        
        Args:
            db_path (str): The file path to the SQLite database. Defaults to "ids_logs.db".
        """
        # Prevent re-init
        if not hasattr(self, 'initialized'):
            self.db_path = db_path
            self.conn: Optional[sqlite3.Connection] = None
            self.connect()
            self._create_tables()
            self.initialized = True

    def connect(self) -> None:
        """
        Establishes a connection to the SQLite database.
        
        Sets the row_factory to sqlite3.Row to allow accessing columns by name.
        """
        try:
            # check_same_thread=False allows connection to be used across multiple threads
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self.conn.row_factory = sqlite3.Row 
            print(f"[DB] Connected to {self.db_path}")
        except sqlite3.Error as e:
            print(f"[DB-ERR] Connection failed: {e}")

    def _create_tables(self) -> None:
        """
        Creates the necessary database schema if tables do not already exist.
        
        Tables created:
        - alerts: Stores detected threats.
        - flow_stats: Stores traffic flow summaries.
        - system_logs: Stores operational events (start/stop, user actions).
        """
        if not self.conn:
            return

        cursor = self.conn.cursor()
        
        # Table 1: Alerts (Threats detected)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                threat_type TEXT,
                src_ip TEXT,
                severity TEXT,
                details TEXT
            )
        ''')

        # Table 2: Flow Stats (Traffic summary)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS flow_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                packet_count INTEGER,
                syn_count INTEGER,
                duration REAL
            )
        ''')
        
        # Table 3: System Events (Start/Stop, User actions)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                event_type TEXT,
                message TEXT,
                user TEXT
            )
        ''')
        
        self.conn.commit()

    def log_alert(self, alert: Dict[str, Any]) -> None:
        """
        Logs a detected threat into the 'alerts' table.

        Args:
            alert (Dict[str, Any]): A dictionary containing alert details.
                Expected keys: 'timestamp', 'threat_type', 'src_ip', 'severity', 'details'.
        """
        if not self.conn:
            return

        try:
            query = '''INSERT INTO alerts (timestamp, threat_type, src_ip, severity, details)
                       VALUES (?, ?, ?, ?, ?)'''
            data = (
                alert.get('timestamp', datetime.now().isoformat()),
                alert.get('threat_type', 'Unknown'),
                alert.get('src_ip', '0.0.0.0'),
                alert.get('severity', 'Low'),
                str(alert.get('details', ''))
            )
            self.conn.execute(query, data)
            self.conn.commit()
        except sqlite3.Error as e:
            print(f"[DB-ERR] Failed to log alert: {e}")

    def log_flow(self, flow_data: Dict[str, Any]) -> None:
        """
        Logs network traffic flow statistics into the 'flow_stats' table.

        Args:
            flow_data (Dict[str, Any]): A dictionary containing flow statistics.
                Expected keys: 'src_ip', 'dst_ip', 'packet_count', 'syn_count', 'duration'.
        """
        if not self.conn:
            return

        try:
            query = '''INSERT INTO flow_stats (timestamp, src_ip, dst_ip, packet_count, syn_count, duration)
                       VALUES (?, ?, ?, ?, ?, ?)'''
            data = (
                datetime.now().isoformat(),
                flow_data.get('src_ip'),
                flow_data.get('dst_ip'),
                flow_data.get('packet_count', 0),
                flow_data.get('syn_count', 0),
                flow_data.get('duration', 0.0)
            )
            self.conn.execute(query, data)
            self.conn.commit()
        except sqlite3.Error as e:
            print(f"[DB-ERR] Failed to log flow: {e}")

    def log_system_event(self, event_type: str, message: str, user: str = "System") -> None:
        """
        Logs operational system events into the 'system_logs' table.

        Args:
            event_type (str): The category of the event (e.g., "INFO", "ERROR", "USER_ACTION").
            message (str): A descriptive message about the event.
            user (str, optional): The user associated with the event. Defaults to "System".
        """
        if not self.conn:
            return

        try:
            query = '''INSERT INTO system_logs (timestamp, event_type, message, user)
                       VALUES (?, ?, ?, ?)'''
            self.conn.execute(query, (datetime.now().isoformat(), event_type, message, user))
            self.conn.commit()
        except sqlite3.Error as e:
            print(f"[DB-ERR] Failed to log system event: {e}")

    def fetch_recent_alerts(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Retrieves the most recent alerts from the database.

        Args:
            limit (int, optional): The maximum number of alerts to retrieve. Defaults to 10.

        Returns:
            List[Dict[str, Any]]: A list of dictionaries, where each dictionary represents an alert row.
        """
        if not self.conn:
            return []

        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
        except sqlite3.Error as e:
            print(f"[DB-ERR] Fetch failed: {e}")
            return []

    def close(self) -> None:
        """
        Closes the database connection cleanly.
        """
        if self.conn:
            self.conn.close()
            print("[DB] Connection closed.")