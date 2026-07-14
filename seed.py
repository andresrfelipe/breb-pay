"""Usuarios demo predefinidos con llaves Bre-B."""

from __future__ import annotations

from werkzeug.security import generate_password_hash

import crypto_service
import db

# Contraseña compartida solo para el prototipo académico.
DEMO_PASSWORD = "demobreb"

DEMO_ACCOUNTS = [
    {
        "username": "ana",
        "full_name": "Ana Pérez",
        "password": DEMO_PASSWORD,
        "balance": 1_500_000.0,
        "breb": {"key_type": "telefono", "key_value": "3001002001"},
    },
    {
        "username": "carlos",
        "full_name": "Carlos Ruiz",
        "password": DEMO_PASSWORD,
        "balance": 2_000_000.0,
        "breb": {"key_type": "email", "key_value": "carlos@brepay.co"},
    },
    {
        "username": "maria",
        "full_name": "María Gómez",
        "password": DEMO_PASSWORD,
        "balance": 850_000.0,
        "breb": {"key_type": "documento", "key_value": "1002003001"},
    },
    {
        "username": "andres",
        "full_name": "Andrés López",
        "password": DEMO_PASSWORD,
        "balance": 1_200_000.0,
        "breb": {"key_type": "alfanumerica", "key_value": "andres.pay"},
    },
]


def seed_demo_users() -> None:
    """Crea los usuarios demo si aún no existen (idempotente)."""
    for account in DEMO_ACCOUNTS:
        existing = db.fetch_one(
            "SELECT id FROM users WHERE username = ?",
            (account["username"],),
        )
        if existing:
            # Asegura llave Bre-B aunque el usuario ya exista.
            key_value = account["breb"]["key_value"]
            if not db.fetch_one("SELECT id FROM breb_keys WHERE key_value = ?", (key_value,)):
                has_primary = db.fetch_one(
                    "SELECT id FROM breb_keys WHERE user_id = ? AND is_primary = 1",
                    (existing["id"],),
                )
                db.execute(
                    """
                    INSERT INTO breb_keys (user_id, key_value, key_type, is_primary)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        existing["id"],
                        key_value,
                        account["breb"]["key_type"],
                        0 if has_primary else 1,
                    ),
                )
            continue

        private_pem, public_pem = crypto_service.generate_rsa_keypair()
        user_id = db.execute(
            """
            INSERT INTO users (
                username, password_hash, full_name, private_key_pem, public_key_pem, balance
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                account["username"],
                generate_password_hash(account["password"]),
                account["full_name"],
                private_pem,
                public_pem,
                account["balance"],
            ),
        )
        db.execute(
            """
            INSERT INTO breb_keys (user_id, key_value, key_type, is_primary)
            VALUES (?, ?, ?, 1)
            """,
            (user_id, account["breb"]["key_value"], account["breb"]["key_type"]),
        )


def public_demo_accounts() -> list[dict]:
    """Datos seguros para mostrar en la UI (sin hashes ni claves)."""
    return [
        {
            "username": a["username"],
            "full_name": a["full_name"],
            "password": a["password"],
            "breb": a["breb"]["key_value"],
            "breb_type": a["breb"]["key_type"],
            "balance": a["balance"],
        }
        for a in DEMO_ACCOUNTS
    ]
