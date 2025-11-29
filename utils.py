import time
import jwt

def create_jwt(payload: dict, secret: str, expire_seconds=3600):
    """Create JWT token dengan waktu kedaluwarsa."""
    data = payload.copy()
    data["exp"] = int(time.time()) + expire_seconds
    return jwt.encode(data, secret, algorithm="HS256")

def decode_jwt(token: str, secret: str):
    """Decode JWT. Return None jika token salah / expired."""
    try:
        return jwt.decode(token, secret, algorithms=["HS256"])
    except:
        return None
