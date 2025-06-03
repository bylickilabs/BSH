# 4. Python-Testskript (für Prototyp und Simulation)

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import time

class BylickiSecureHybrid:
    def __init__(self):
        self.private_key = x25519.X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        self.session_key = None

    def generate_session_key(self, peer_public_bytes):
        peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
        shared_key = self.private_key.exchange(peer_public_key)
        self.session_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'Bylicki Secure Session Key'
        ).derive(shared_key)

    def encrypt(self, plaintext: bytes):
        if self.session_key is None:
            raise Exception("Session key not generated.")
        nonce = os.urandom(12)
        aesgcm = AESGCM(self.session_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return nonce + ciphertext

    def decrypt(self, data: bytes):
        if self.session_key is None:
            raise Exception("Session key not generated.")
        nonce = data[:12]
        ciphertext = data[12:]
        aesgcm = AESGCM(self.session_key)
        return aesgcm.decrypt(nonce, ciphertext, None)

    def rotate_key(self):
        if self.session_key is None:
            raise Exception("Session key not generated.")
        timestamp = int(time.time()).to_bytes(8, 'big')
        self.session_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'Bylicki Key Rotation' + timestamp
        ).derive(self.session_key)

if __name__ == "__main__":
    partner = x25519.X25519PrivateKey.generate()
    partner_pub = partner.public_key().public_bytes()
    bsh = BylickiSecureHybrid()
    bsh.generate_session_key(partner_pub)

    msg = b"Top secret data"
    encrypted = bsh.encrypt(msg)
    print(f"Encrypted: {encrypted.hex()}")

    bsh_partner = BylickiSecureHybrid()
    bsh_partner.private_key = partner
    bsh_partner.generate_session_key(bsh.public_key.public_bytes())
    decrypted = bsh_partner.decrypt(encrypted)
    print(f"Decrypted: {decrypted.decode()}")
