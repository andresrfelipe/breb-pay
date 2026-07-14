"""
Módulo de criptografía RSA para Bre-Pay.

Propiedades que garantiza:
- Autenticidad e integridad: firma digital RSA-PSS + SHA-256
- No repudio: solo el dueño de la clave privada puede firmar
- Confidencialidad: cifrado híbrido RSA-OAEP + AES-256-GCM
  (RSA cifra la clave AES; AES cifra el payload de la orden)
"""

from __future__ import annotations

import base64
import json
import os
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


RSA_KEY_SIZE = 2048


def generate_rsa_keypair() -> tuple[str, str]:
    """Genera un par RSA y lo serializa en PEM (privada PKCS8, pública SubjectPublicKeyInfo)."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_SIZE)
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    return private_pem, public_pem


def _load_private(pem: str):
    return serialization.load_pem_private_key(pem.encode("utf-8"), password=None)


def _load_public(pem: str):
    return serialization.load_pem_public_key(pem.encode("utf-8"))


def _canonical_payload(payload: dict[str, Any]) -> bytes:
    """Serialización canónica para firmas reproducibles."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def payload_hash(payload: dict[str, Any]) -> str:
    """SHA-256 hex del payload canónico (paso intermedio del panel de confianza)."""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(_canonical_payload(payload))
    return digest.finalize().hex()


def public_key_fingerprint(public_pem: str) -> str:
    """Huella corta SHA-256 de la clave pública (para mostrar en UI)."""
    dig = hashes.Hash(hashes.SHA256())
    dig.update(public_pem.encode("utf-8"))
    return dig.finalize().hex()[:16]


def sign_payload(private_pem: str, payload: dict[str, Any]) -> str:
    """Firma el payload con RSA-PSS. Devuelve firma en Base64."""
    private_key = _load_private(private_pem)
    signature = private_key.sign(
        _canonical_payload(payload),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return base64.b64encode(signature).decode("utf-8")


def verify_signature(public_pem: str, payload: dict[str, Any], signature_b64: str) -> bool:
    """Verifica la firma RSA-PSS de un payload. Devuelve True/False."""
    public_key = _load_public(public_pem)
    try:
        public_key.verify(
            base64.b64decode(signature_b64),
            _canonical_payload(payload),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


def encrypt_for_recipient(recipient_public_pem: str, plaintext: bytes) -> dict[str, str]:
    """
    Cifrado híbrido:
    1) AES-256-GCM cifra el mensaje
    2) RSA-OAEP cifra la clave AES con la pública del destinatario
    """
    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    public_key = _load_public(recipient_public_pem)
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return {
        "encrypted_key": base64.b64encode(encrypted_key).decode("utf-8"),
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
    }


def decrypt_for_recipient(recipient_private_pem: str, envelope: dict[str, str]) -> bytes:
    """Descifra un sobre híbrido con la clave privada del destinatario."""
    private_key = _load_private(recipient_private_pem)
    aes_key = private_key.decrypt(
        base64.b64decode(envelope["encrypted_key"]),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(
        base64.b64decode(envelope["nonce"]),
        base64.b64decode(envelope["ciphertext"]),
        None,
    )


def encrypt_json(recipient_public_pem: str, data: dict[str, Any]) -> dict[str, str]:
    return encrypt_for_recipient(
        recipient_public_pem,
        json.dumps(data, ensure_ascii=False).encode("utf-8"),
    )


def decrypt_json(recipient_private_pem: str, envelope: dict[str, str]) -> dict[str, Any]:
    raw = decrypt_for_recipient(recipient_private_pem, envelope)
    return json.loads(raw.decode("utf-8"))
