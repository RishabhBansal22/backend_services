from config import settings
from functions import smtp_send_mail, test_passreset_flow
import random
import redis
import json

def redis_conn():
    """
    Create and test a Redis connection.
    Returns a Redis connection object if successful.
    Raises redis.RedisError if connection fails.
    """
    try:
        conn = redis.Redis(
            host=settings.redis_host,
            port=settings.redis_port,
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

def forget_pass_listner(test_flow=False):
    """
    Continuously listen for password reset email requests on Redis pub/sub.
    Subscribes to 'email:reset_pass' channel and processes incoming messages.
    """
    r = redis_conn()
    pubsub = r.pubsub()
    
    # Subscribe to the channel that auth service publishes to
    pubsub.subscribe("email:reset_pass")
    
    print("📨 Email service listening on channel: email:reset_pass")
    
    # Continuously listen for messages
    for message in pubsub.listen():
        if message["type"] == "message":
            try:
                data = json.loads(message["data"])
                print(f"📧 Received email request: {data}")
                
                # Extract data from message
                email = data.get("email")
                reset_token = data.get("reset_token")
                expire = data.get("expires_in")
                
                if not email or not reset_token or not expire:
                    print(f"Invalid message format: {data}")
                    continue
                
                # Send the email
                result = smtp_send_mail(email, reset_token, expire)
                print(f"✅ Email sent: {result}")

                if test_flow:
                    req = test_passreset_flow(reset_token)
                    print(req)
                
            except json.JSONDecodeError as e:
                print(f"❌ JSON decode error: {e}")
            except Exception as e:
                print(f"❌ Error processing message: {e}")
 

if __name__ == "__main__":
    print("🚀 Starting email service...")
    try:
        forget_pass_listner(test_flow=False)
    except KeyboardInterrupt:
        print("\n👋 Email service stopped by user")
    except Exception as e:
        print(f"❌ Email service crashed: {e}")