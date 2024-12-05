import time
from classes.packet import Packet
from classes.blockchain_session import BlockchainSession
from utils.signature import *
from utils.key import *

def main():
    # Generate client and server keys
    client_private, client_public = generate_keys()
    server_private, server_public = generate_keys()

    # Step 1: Time-Locked Authentication
    timestamp = int(time.time())
    nonce = "random_nonce"
    signature = sign_time_nonce(server_private, timestamp, nonce)
    auth_verified = verify_signature(server_public, timestamp, nonce, signature)
    print(f"Authentication Verified: {auth_verified}")

    # Step 2: Blockchain-Inspired Integrity
    session = BlockchainSession(session_id="SESSION123")
    packet1 = Packet(data="Hello, World!", prev_hash="", timestamp=timestamp, session_id="SESSION123")
    session.add_packet(packet1)

    packet2 = Packet(data="Another message", prev_hash="", timestamp=timestamp + 1, session_id="SESSION123")
    session.add_packet(packet2)

    # Verify the blockchain integrity
    print(f"Blockchain Integrity Verified: {session.verify_chain()}")

    # Tamper with a packet
    session.chain[1].data = "Tampered message"
    print(f"Blockchain Integrity After Tampering: {session.verify_chain()}")

if __name__ == "__main__":
    main()