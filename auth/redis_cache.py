import redis
from config import settings

conn = redis.Redis(host=settings.REDIS_HOST,port=settings.REDIS_PORT,db=0)
try:
    conn_check = conn.ping()
except Exception as e:
    print(e)

