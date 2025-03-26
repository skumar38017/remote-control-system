# redis.py

# redis.py
import json
import time
from Config import Config

class RedisManager:
    def __init__(self):
        self.config = Config()
        self.redis_client = self._connect_redis()

    def _connect_redis(self):
        """Establishes and returns a Redis connection."""
        if self.config.check_redis_connection():
            return self.config.redis_connection
        else:
            self.config._connect_redis()
            return self.config.redis_connection

    def get_devices(self, network_range):
        """Fetches stored device data from Redis."""
        try:
            data = self.redis_client.get(f"devices:{network_range}")
            if data:
                return json.loads(data)
        except Exception as e:
            print(f"Redis error: {e}")
        return None

    def store_devices(self, network_range, devices):
        """Stores device data in Redis with timestamp."""
        try:
            data = {
                'timestamp': time.time(),
                'devices': devices
            }
            self.redis_client.set(f"devices:{network_range}", json.dumps(data), ex=3600)
            return True
        except Exception as e:
            print(f"Redis store error: {e}")
            return False

    def get_client(self):
        """Returns the Redis client instance."""
        return self.redis_client