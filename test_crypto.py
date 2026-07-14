"""Prueba end-to-end del flujo crypto sin levantar el servidor HTTP."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import crypto_service


def main() -> None:
    priv_a, pub_a = crypto_service.generate_rsa_keypair()
    priv_b, pub_b = crypto_service.generate_rsa_keypair()

    order = {
        "txid": "demo-1",
        "sender_username": "alice",
        "receiver_breb": "3001112233",
        "amount": 15000.0,
        "currency": "COP",
        "note": "almuerzo",
    }

    signature = crypto_service.sign_payload(priv_a, order)
    assert crypto_service.verify_signature(pub_a, order, signature), "firma válida esperada"

    digest = crypto_service.payload_hash(order)
    assert len(digest) == 64 and all(c in "0123456789abcdef" for c in digest)

    tampered = dict(order)
    tampered["amount"] = 999999.0
    assert crypto_service.payload_hash(tampered) != digest
    assert not crypto_service.verify_signature(pub_a, tampered, signature), "tamper debe fallar"

    envelope = crypto_service.encrypt_json(pub_b, order)
    decrypted = crypto_service.decrypt_json(priv_b, envelope)
    assert decrypted == order, "descifrado debe coincidir"

    try:
        crypto_service.decrypt_json(priv_a, envelope)
        raise AssertionError("Alice no debería poder descifrar el sobre de Bob")
    except Exception:
        pass

    print("OK — firma, integridad, cifrado híbrido y exclusividad del destinatario")
    print(json.dumps({"signature_len": len(signature), "envelope_keys": list(envelope)}, indent=2))


if __name__ == "__main__":
    main()
