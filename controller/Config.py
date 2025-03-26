#  controller/Config.py

# controller/Config.py

import redis
from controller.settings import Settings

# initialize Settings
Settings = Settings()

class Config:
    """
    Application configuration manager for Redis connection.
    """
    def __init__(self):
        self._redis_connection = None

    @property
    def redis_connection(self) -> redis.Redis:
        """Returns the Redis connection instance, creating it if necessary."""
        if self._redis_connection is None:
            self._connect_redis()
        return self._redis_connection

    def _connect_redis(self):
        """Establishes a Redis connection and handles connection errors."""
        try:
            self._redis_connection = redis.Redis(
                host=Settings.REDIS_HOST,
                port=Settings.REDIS_PORT,
                password=Settings.REDIS_PASSWORD,
                db=Settings.REDIS_DB_CACHE
            )
            # Test the connection
            self._redis_connection.ping()
            print("Redis connection established successfully.")
        except redis.ConnectionError as e:
            print(f"Error connecting to Redis: {e}")
            raise  # Re-raise the exception to be handled by the caller

    def check_redis_connection(self) -> bool:
        """Checks if the Redis connection is alive."""
        if self._redis_connection is None:
            return False
        try:
            self._redis_connection.ping()
            return True
        except redis.ConnectionError:
            return False