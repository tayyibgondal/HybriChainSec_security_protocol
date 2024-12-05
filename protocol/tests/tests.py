import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
# ---------------------------------------------------------------------------------
import unittest
import time
import hashlib
from classes.blockchain_session import BlockchainSession
from classes.packet import Packet
from utils.key import generate_keys
from utils.signature import sign_time_nonce, verify_signature



class TestKeyUtils(unittest.TestCase):
    """Test cases for key generation and signature utilities."""

    def test_generate_keys(self):
        """Test that generate_keys produces distinct private and public keys."""
        private_key, public_key = generate_keys()
        self.assertIsNotNone(private_key)
        self.assertIsNotNone(public_key)
        self.assertNotEqual(private_key, public_key)

    def test_sign_and_verify_signature(self):
        """Test signing and verifying a time-stamped nonce."""
        private_key, public_key = generate_keys()
        timestamp = int(time.time())
        nonce = "random_nonce"
        signature = sign_time_nonce(private_key, timestamp, nonce)
        self.assertTrue(verify_signature(public_key, timestamp, nonce, signature))

        # Verify with tampered data
        self.assertFalse(verify_signature(public_key, timestamp, "wrong_nonce", signature))
        self.assertFalse(verify_signature(public_key, timestamp + 1, nonce, signature))


class TestPacket(unittest.TestCase):
    """Test cases for the Packet class."""

    def test_compute_hash(self):
        """Test the hash computation of a packet."""
        packet = Packet(data="Test data", prev_hash="0", timestamp=1234567890, session_id="SESSION123")
        expected_hash = hashlib.sha256(b"Test data:0:1234567890:SESSION123").hexdigest()
        self.assertEqual(packet.compute_hash(), expected_hash)


class TestBlockchainSession(unittest.TestCase):
    """Test cases for the BlockchainSession class."""

    def test_add_packet(self):
        """Test adding packets to the blockchain session."""
        session = BlockchainSession(session_id="SESSION123")
        packet1 = Packet(data="First packet", prev_hash="", timestamp=1234567890, session_id="SESSION123")
        session.add_packet(packet1)
        self.assertEqual(len(session.chain), 1)
        self.assertEqual(session.chain[0].prev_hash, "0")

        packet2 = Packet(data="Second packet", prev_hash="", timestamp=1234567891, session_id="SESSION123")
        session.add_packet(packet2)
        self.assertEqual(len(session.chain), 2)
        self.assertEqual(session.chain[1].prev_hash, packet1.compute_hash())

    def test_verify_chain(self):
        """Test verifying the integrity of the blockchain."""
        session = BlockchainSession(session_id="SESSION123")
        packet1 = Packet(data="First packet", prev_hash="", timestamp=1234567890, session_id="SESSION123")
        session.add_packet(packet1)

        packet2 = Packet(data="Second packet", prev_hash="", timestamp=1234567891, session_id="SESSION123")
        session.add_packet(packet2)

        # Verify the blockchain
        self.assertTrue(session.verify_chain())

        # Tamper with a packet
        session.chain[1].data = "Tampered packet"
        self.assertTrue(session.verify_chain())


class TestIntegration(unittest.TestCase):
    """Integration tests for the overall functionality."""

    def test_full_workflow(self):
        """Test the complete authentication and blockchain integrity workflow."""
        # Generate keys
        client_private, client_public = generate_keys()
        server_private, server_public = generate_keys()

        # Step 1: Time-Locked Authentication
        timestamp = int(time.time())
        nonce = "random_nonce"
        signature = sign_time_nonce(server_private, timestamp, nonce)
        self.assertTrue(verify_signature(server_public, timestamp, nonce, signature))

        # Step 2: Blockchain-Inspired Integrity
        session = BlockchainSession(session_id="SESSION123")
        packet1 = Packet(data="Hello, World!", prev_hash="", timestamp=timestamp, session_id="SESSION123")
        session.add_packet(packet1)

        packet2 = Packet(data="Another message", prev_hash="", timestamp=timestamp + 1, session_id="SESSION123")
        session.add_packet(packet2)

        # Verify the blockchain integrity
        self.assertTrue(session.verify_chain())

        # Tamper with a packet
        session.chain[1].data = "Tampered message"
        self.assertTrue(session.verify_chain())


if __name__ == "__main__":
    unittest.main()
