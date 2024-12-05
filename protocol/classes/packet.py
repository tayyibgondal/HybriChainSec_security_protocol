import hashlib

class Packet:
    """Represents a single data packet in the session."""
    def __init__(self, data, prev_hash, timestamp, session_id):
        self.data = data
        self._prev_hash = prev_hash
        self.timestamp = timestamp
        self.session_id = session_id

    @property
    def prev_hash(self):
        return self._prev_hash

    def set_prev_hash(self, hash_value):
        """Set the previous hash if it hasn't been set already."""
        if not self._prev_hash:  # Allow only if it's not already set
            self._prev_hash = hash_value

    def compute_hash(self):
        """Compute the hash of the packet."""
        content = f"{self.data}:{self.prev_hash}:{self.timestamp}:{self.session_id}".encode()
        return hashlib.sha256(content).hexdigest()
