"""Pruebas de integración del flujo crítico de transferencia (ítem 5.2)."""

from __future__ import annotations

import json

import crypto_service
import db
from app import app


def _reset() -> None:
    if db.DB_PATH.exists():
        db.DB_PATH.unlink()
    db.init_db()


def _register(client, username: str, full_name: str, password: str = "secret12") -> None:
    assert client.post(
        "/register",
        data={"username": username, "full_name": full_name, "password": password},
        follow_redirects=True,
    ).status_code == 200


def _login(client, username: str, password: str = "secret12") -> None:
    assert client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=True,
    ).status_code == 200


def test_transfer_signature_ok_and_tamper() -> None:
    _reset()
    client = app.test_client()
    _register(client, "bob", "Bob Demo")
    assert client.post(
        "/breb",
        data={"key_type": "telefono", "key_value": "3001112233"},
        follow_redirects=True,
    ).status_code == 200
    client.get("/logout", follow_redirects=True)

    _register(client, "alice", "Alice Demo")
    assert client.post(
        "/breb",
        data={"key_type": "alfanumerica", "key_value": "alicepay01"},  # se antepone @
        follow_redirects=True,
    ).status_code == 200

    key = db.fetch_one("SELECT * FROM breb_keys WHERE key_value = ?", ("@alicepay01",))
    assert key is not None

    resp = client.post(
        "/api/transfers",
        json={
            "receiver_breb": "3001112233",
            "amount": 15000,
            "note": "almuerzo",
            "confirm_password": "secret12",
        },
    )
    assert resp.status_code == 201
    data = resp.get_json()
    assert data["ok"] is True
    tx_id = data["tx_id"]

    ok = client.post(f"/api/verify/{tx_id}", json={"tamper": False}).get_json()
    bad = client.post(f"/api/verify/{tx_id}", json={"tamper": True}).get_json()
    assert ok["valid"] is True
    assert bad["valid"] is False

    tx = db.fetch_one("SELECT * FROM transactions WHERE id = ?", (tx_id,))
    payload = json.loads(tx["payload_json"])
    sender = db.fetch_one("SELECT public_key_pem FROM users WHERE username = 'alice'")
    assert crypto_service.verify_signature(sender["public_key_pem"], payload, tx["signature_b64"])


def test_insufficient_balance() -> None:
    _reset()
    client = app.test_client()
    _register(client, "bob", "Bob Demo")
    client.post("/breb", data={"key_type": "documento", "key_value": "1000000"}, follow_redirects=True)
    client.get("/logout", follow_redirects=True)

    _register(client, "alice", "Alice Demo")
    resp = client.post(
        "/api/transfers",
        json={
            "receiver_breb": "1000000",
            "amount": 9_999_999,
            "confirm_password": "secret12",
        },
    )
    assert resp.status_code == 400
    assert "insuficiente" in resp.get_json()["error"].lower()
    assert db.fetch_one("SELECT COUNT(*) AS c FROM transactions")["c"] == 0


def test_transfer_requires_password_confirmation() -> None:
    _reset()
    client = app.test_client()
    _register(client, "bob", "Bob Demo")
    client.post("/breb", data={"key_type": "email", "key_value": "bob@example.com"}, follow_redirects=True)
    client.get("/logout", follow_redirects=True)
    _register(client, "alice", "Alice Demo")

    resp = client.post(
        "/api/transfers",
        json={"receiver_breb": "bob@example.com", "amount": 10, "confirm_password": "wrong"},
    )
    assert resp.status_code == 401


def test_api_me_and_health() -> None:
    _reset()
    client = app.test_client()
    assert client.get("/api/health").get_json()["ok"] is True
    _register(client, "alice", "Alice Demo")
    me = client.get("/api/me").get_json()
    assert me["ok"] is True
    assert me["user"]["username"] == "alice"
    assert client.get("/api/docs").status_code == 200
    assert client.get("/api/openapi.json").status_code == 200


def main() -> None:
    test_api_me_and_health()
    test_transfer_requires_password_confirmation()
    test_insufficient_balance()
    test_transfer_signature_ok_and_tamper()
    print("OK integración — firma, tamper, saldo insuficiente, API REST")


if __name__ == "__main__":
    main()
