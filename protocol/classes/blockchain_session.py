class BlockchainSession:
    """Manages the session using a blockchain-inspired structure."""
    def __init__(self, session_id):
        self.session_id = session_id
        self.chain = []

    def add_packet(self, packet):
        """Add a packet to the blockchain session."""
        if len(self.chain) > 0:
            packet.set_prev_hash(self.chain[-1].compute_hash())
        else:
            packet.set_prev_hash("0")  # Genesis block
        self.chain.append(packet)

    def verify_chain(self):
        """Verify the integrity of the blockchain session."""
        for i in range(1, len(self.chain)):
            current_packet = self.chain[i]
            prev_packet = self.chain[i - 1]
            
            # Check if the previous hash stored in the current packet matches the hash of the previous packet
            if current_packet.prev_hash != prev_packet.compute_hash():
                return False

        # Check genesis block's previous hash
        if len(self.chain) > 0 and self.chain[0].prev_hash != "0":
            return False

        return True

