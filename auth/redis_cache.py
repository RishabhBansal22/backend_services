import redis
from config import settings

def redis_conn():
    """
    Create and test a Redis connection.
    Returns a Redis connection object if successful.
    Raises redis.RedisError if connection fails.
    """
    try:
        conn = redis.Redis(
            host=settings.REDIS_HOST,
            port=settings.REDIS_PORT,
            db=0,
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=5,
            retry_on_timeout=True
        )
        # Test the connection
        conn.ping()
        print(conn.ping())
        return conn
    except redis.RedisError as e:
        print(f"Redis connection error: {e}")
        raise redis.RedisError(f"Failed to connect to Redis: {e}")
    except Exception as e:
        print(f"Unexpected error connecting to Redis: {e}")
        raise Exception(f"Failed to connect to Redis: {e}")

# Initialize the global connection
try:
    conn = redis_conn()
    print("Redis connection established successfully")
except Exception as e:
    print(f"Warning: Redis connection failed: {e}")
    conn = None

