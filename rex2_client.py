import os
import time
import uuid

import keyring
import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

SERVER = "http://localhost:5001"


def device_fingerprint():
    # Replace with robust platform-specific fingerprint or attestation.
    # Example: hashed tuple of MAC addresses + stable disk id + platform.
    import hashlib

    mac = hex(uuid.getnode())
    uname = os.uname().sysname + "-" + os.uname().nodename
    s = f"{mac}|{uname}"
    return hashlib.sha256(s.encode()).hexdigest()


def generate_device_keypair():
    priv = ec.generate_private_key(ec.SECP256R1())
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    # store private key in keyring (for PoC). On macOS use Keychain/secure enclave if possible.
    keyring.set_password("Rex2.0", "device_private_key", priv_pem.decode())
    return priv, priv_pem, pub_pem


def load_private_key_from_keyring():
    val = keyring.get_password("Rex2.0", "device_private_key")
    if not val:
        return None
    return serialization.load_pem_private_key(val.encode(), password=None)


def register_and_prove(device_id, priv, pub_pem, fingerprint):
    # register
    r = requests.post(
        f"{SERVER}/register",
        json={
            "device_id": device_id,
            "pubkey_pem": pub_pem.decode(),
            "fingerprint": fingerprint,
        },
    )
    r.raise_for_status()
    challenge = r.json()["challenge"]
    # sign challenge
    sig = priv.sign(challenge.encode(), ec.ECDSA(hashes.SHA256()))
    sig_hex = sig.hex()
    r2 = requests.post(
        f"{SERVER}/prove",
        json={"device_id": device_id, "signature_hex": sig_hex},
    )
    r2.raise_for_status()
    data = r2.json()
    license_jwt = data["license_jwt"]
    server_pub = data["server_pub_pem"]
    # store license locally (in secure store)
    keyring.set_password("Rex2.0", "license_jwt", license_jwt)
    keyring.set_password("Rex2.0", "server_pub", server_pub)
    return license_jwt


def send_heartbeat(device_id, priv, fingerprint):
    license_jwt = keyring.get_password("Rex2.0", "license_jwt")
    # build canonical string and sign
    ts = str(int(time.time()))
    # license id must be decoded from JWT, but we can send the JWT as-is and let server decode
    # canonical string:
    canonical = (
        f"{device_id}|{fingerprint}|{ts}|{''}"
    )  # server will compute license_id from jwt; include empty placeholder or decode on client
    # better: decode license to get license_id client-side via PyJWT if needed
    sig = priv.sign(canonical.encode(), ec.ECDSA(hashes.SHA256()))
    r = requests.post(
        f"{SERVER}/heartbeat",
        json={
            "license_jwt": license_jwt,
            "device_id": device_id,
            "fingerprint": fingerprint,
            "ts": ts,
            "signature_hex": sig.hex(),
        },
    )
    print(r.json())


def main():
    device_id = uuid.uuid4().hex
    fingerprint = device_fingerprint()
    # try load or generate
    priv = load_private_key_from_keyring()
    if not priv:
        priv, priv_pem, pub_pem = generate_device_keypair()
    else:
        pub_pem = priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    license_jwt = keyring.get_password("Rex2.0", "license_jwt")
    if not license_jwt:
        license_jwt = register_and_prove(device_id, priv, pub_pem, fingerprint)
    # periodic heartbeat
    for _ in range(5):
        send_heartbeat(device_id, priv, fingerprint)
        time.sleep(5)


if __name__ == "__main__":
    main()
