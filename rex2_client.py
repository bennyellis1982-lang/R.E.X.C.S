"""
Rex2 device client for registration and heartbeat proof-of-life.

This module encapsulates device identity generation, license registration,
and periodic heartbeat signing. It uses the system keyring for storing
secrets so that we avoid persisting private keys in the working tree.
"""
from __future__ import annotations

import hashlib
import logging
import os
import time
import uuid
from dataclasses import dataclass
from typing import Optional, Tuple

import keyring
import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


DEVICE_KEY_SERVICE = "Rex2.0"
DEVICE_PRIVATE_KEY = "device_private_key"
DEVICE_ID_KEY = "device_id"
LICENSE_KEY = "license_jwt"
SERVER_PUB_KEY = "server_pub"


def _derive_device_fingerprint() -> str:
    """Generate a stable device fingerprint for the current host."""
    mac = hex(uuid.getnode())
    uname = f"{os.uname().sysname}-{os.uname().nodename}"
    return hashlib.sha256(f"{mac}|{uname}".encode()).hexdigest()


def _load_private_key_from_keyring() -> Optional[ec.EllipticCurvePrivateKey]:
    value = keyring.get_password(DEVICE_KEY_SERVICE, DEVICE_PRIVATE_KEY)
    if not value:
        return None
    return serialization.load_pem_private_key(value.encode(), password=None)


def _generate_device_keypair() -> Tuple[ec.EllipticCurvePrivateKey, bytes, bytes]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    keyring.set_password(DEVICE_KEY_SERVICE, DEVICE_PRIVATE_KEY, priv_pem.decode())
    return private_key, priv_pem, pub_pem


def _load_or_create_device_id() -> str:
    device_id = keyring.get_password(DEVICE_KEY_SERVICE, DEVICE_ID_KEY)
    if device_id:
        return device_id

    device_id = uuid.uuid4().hex
    keyring.set_password(DEVICE_KEY_SERVICE, DEVICE_ID_KEY, device_id)
    return device_id


@dataclass
class RexClientConfig:
    server_url: str = os.getenv("REX_SERVER_URL", "http://localhost:5001")
    request_timeout_seconds: int = 10


class RexClient:
    def __init__(self, config: Optional[RexClientConfig] = None) -> None:
        self.config = config or RexClientConfig()
        self.device_id = _load_or_create_device_id()
        self.fingerprint = _derive_device_fingerprint()

    def _post(self, path: str, payload: dict) -> dict:
        url = self.config.server_url.rstrip("/") + path
        response = requests.post(url, json=payload, timeout=self.config.request_timeout_seconds)
        response.raise_for_status()
        return response.json()

    def _load_or_generate_key(self) -> Tuple[ec.EllipticCurvePrivateKey, bytes]:
        private_key = _load_private_key_from_keyring()
        if private_key:
            return private_key, private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

        private_key, _, public_pem = _generate_device_keypair()
        return private_key, public_pem

    def register_and_prove(self) -> str:
        private_key, public_pem = self._load_or_generate_key()
        registration = self._post(
            "/register",
            {
                "device_id": self.device_id,
                "pubkey_pem": public_pem.decode(),
                "fingerprint": self.fingerprint,
            },
        )
        challenge = registration["challenge"]

        signature = private_key.sign(challenge.encode(), ec.ECDSA(hashes.SHA256()))
        proof = self._post(
            "/prove",
            {"device_id": self.device_id, "signature_hex": signature.hex()},
        )

        license_jwt = proof["license_jwt"]
        server_pub = proof["server_pub_pem"]

        keyring.set_password(DEVICE_KEY_SERVICE, LICENSE_KEY, license_jwt)
        keyring.set_password(DEVICE_KEY_SERVICE, SERVER_PUB_KEY, server_pub)
        return license_jwt

    def send_heartbeat(self) -> dict:
        private_key, _ = self._load_or_generate_key()
        license_jwt = keyring.get_password(DEVICE_KEY_SERVICE, LICENSE_KEY)
        if not license_jwt:
            raise RuntimeError("No license JWT available. Run registration first.")

        timestamp = str(int(time.time()))
        canonical = f"{self.device_id}|{self.fingerprint}|{timestamp}|"
        signature = private_key.sign(canonical.encode(), ec.ECDSA(hashes.SHA256()))

        heartbeat = self._post(
            "/heartbeat",
            {
                "license_jwt": license_jwt,
                "device_id": self.device_id,
                "fingerprint": self.fingerprint,
                "ts": timestamp,
                "signature_hex": signature.hex(),
            },
        )
        return heartbeat

    def run_loop(self, delay_seconds: int = 5, count: int = 5) -> None:
        license_jwt = keyring.get_password(DEVICE_KEY_SERVICE, LICENSE_KEY)
        if not license_jwt:
            logging.info("No license detected; registering device")
            self.register_and_prove()

        for _ in range(count):
            heartbeat = self.send_heartbeat()
            logging.info("Heartbeat response: %s", heartbeat)
            time.sleep(delay_seconds)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    client = RexClient()
    client.run_loop()


if __name__ == "__main__":
    main()
