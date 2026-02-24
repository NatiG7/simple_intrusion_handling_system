import os
from datetime import datetime
from typing import List, Dict, Any, Optional
from pymongo import MongoClient, errors

class DatabaseManager:
    """
    Singleton class for handling MongoDB database interactions.

    This class manages the connection to the MongoDB instance and provides
    methods for logging alerts, network flow statistics, and system events.
    It implements the Singleton pattern to ensure a single database connection
    instance throughout the application's lifecycle.
    """
    _instance: Optional['DatabaseManager'] = None

    def __new__(cls, *args: Any, **kwargs: Any) -> 'DatabaseManager':
        """
        Singleton Pattern: Ensures only one instance of DatabaseManager exists.

        Returns:
            DatabaseManager: The singleton instance.
        """
        if not cls._instance:
            cls._instance = super(DatabaseManager, cls).__new__(cls)
        return cls._instance

    def __init__(self, uri: str = "mongodb://localhost:27017/", db_name: str = "ids_db") -> None:
        """
        Initializes the MongoDB connection.

        Args:
            uri (str): The MongoDB connection string. Defaults to local default.
            db_name (str): The name of the database to use. Defaults to "ids_db".
        """
        if not hasattr(self, 'initialized'):
            # Allow environment variable override for Docker compatibility
            self.uri = os.getenv("MONGO_URI", uri)
            self.db_name = os.getenv("MONGO_DB_NAME", db_name)
            self.client: Optional[MongoClient] = None
            self.db: Any = None
            
            self.connect()
            self.initialized = True

    def connect(self) -> None:
        """
        Establishes a connection to the MongoDB server and initializes collections.
        
        Raises:
            ConnectionFailure: If the server is unreachable (handled internally).
        """
        try:
            self.client = MongoClient(self.uri, serverSelectionTimeoutMS=5000)
            # Trigger a ping to verify connection
            self.client.admin.command('ping')
            
            self.db = self.client[self.db_name]
            print(f"[DB] Connected to MongoDB at {self.uri} (Database: {self.db_name})")
            
            self._init_indexes()
            
        except errors.ServerSelectionTimeoutError as e:
            print(f"[DB-ERR] Connection failed: {e}")

    def _init_indexes(self) -> None:
        """
        Creates indexes on the 'timestamp' field for all collections to optimize query performance.
        This is safe to run multiple times (indexes are not duplicated).
        """
        if self.db is not None:
            self.db.alerts.create_index("timestamp")
            self.db.flow_stats.create_index("timestamp")
            self.db.system_logs.create_index("timestamp")

    def log_alert(self, alert: Dict[str, Any]) -> None:
        """
        Logs a detected threat into the 'alerts' collection.

        Args:
            alert (Dict[str, Any]): A dictionary containing alert details.
        """
        if self.db is None:
            return

        try:
            # Ensure timestamp exists
            if 'timestamp' not in alert:
                alert['timestamp'] = datetime.now().isoformat()
            
            self.db.alerts.insert_one(alert)
        except Exception as e:
            print(f"[DB-ERR] Failed to log alert: {e}")
            
    def log_alerts_batch(self, alerts: List[Dict])->None:
        if not self.db:
            return
        try:
            for alert in alerts:
                if 'timestamp' not in alert:
                    alert['timestamp'] = datetime.now().isoformat()
            self.db.alerts.insert_many(alerts)
        except Exception as e:
            print(f"[DB-ERR] Batch insert failure : {e}")

    def log_flow(self, flow_data: Dict[str, Any]) -> None:
        """
        Logs network traffic flow statistics into the 'flow_stats' collection.

        Args:
            flow_data (Dict[str, Any]): A dictionary containing flow statistics.
        """
        if self.db is None:
            return

        try:
            if 'timestamp' not in flow_data:
                flow_data['timestamp'] = datetime.now().isoformat()
                
            self.db.flow_stats.insert_one(flow_data)
        except Exception as e:
            print(f"[DB-ERR] Failed to log flow: {e}")

    def log_system_event(self, event_type: str, message: str, user: str = "System") -> None:
        """
        Logs operational system events into the 'system_logs' collection.

        Args:
            event_type (str): The category of the event (e.g., "INFO", "ERROR").
            message (str): A descriptive message about the event.
            user (str, optional): The user associated with the event. Defaults to "System".
        """
        if self.db is None:
            return

        try:
            log_entry = {
                "timestamp": datetime.now().isoformat(),
                "event_type": event_type,
                "message": message,
                "user": user
            }
            self.db.system_logs.insert_one(log_entry)
        except Exception as e:
            print(f"[DB-ERR] Failed to log system event: {e}")

    def fetch_recent_alerts(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Retrieves the most recent alerts from the database.

        Args:
            limit (int, optional): The maximum number of alerts to retrieve. Defaults to 10.

        Returns:
            List[Dict[str, Any]]: A list of alert dictionaries. ObjectIds are converted to strings.
        """
        if self.db is None:
            return []

        try:
            # Sort by _id descending (which is effectively time-based in Mongo)
            cursor = self.db.alerts.find().sort("_id", -1).limit(limit)
            
            alerts = []
            for doc in cursor:
                # Convert ObjectId to string for JSON serialization safety
                doc['_id'] = str(doc['_id'])
                alerts.append(doc)
            return alerts
        except Exception as e:
            print(f"[DB-ERR] Fetch failed: {e}")
            return []

    def close(self) -> None:
        """Closes the MongoDB connection cleanly."""
        if self.client:
            self.client.close()
            print("[DB] Connection closed.")