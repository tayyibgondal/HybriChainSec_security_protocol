from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.hashes import SHA256

def sign_time_nonce(private_key, timestamp, nonce):
    """Sign a timestamp + nonce with a private key."""
    message = f"{timestamp}:{nonce}".encode()
    signature = private_key.sign(message, PKCS1v15(), SHA256())
    return signature

def verify_signature(public_key, timestamp, nonce, signature):
    """Verify the timestamp + nonce signature."""
    message = f"{timestamp}:{nonce}".encode()
    try:
        public_key.verify(signature, message, PKCS1v15(), SHA256())
        return True
    except Exception as e:
        return False