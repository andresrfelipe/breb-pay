"""Prueba HTTP end-to-end con el test client de Flask."""

from __future__ import annotations

import db
from app import app


def main() -> None:
    if db.DB_PATH.exists():
        db.DB_PATH.unlink()
    db.init_db()

    client = app.test_client()

    assert client.post(
        "/register",
        data={"username": "alice", "full_name": "Alice Demo", "password": "secret1"},
        follow_redirects=True,
    ).status_code == 200
    client.get("/logout", follow_redirects=True)

    assert client.post(
        "/register",
        data={"username": "bob", "full_name": "Bob Demo", "password": "secret1"},
        follow_redirects=True,
    ).status_code == 200

    resp = client.post(
        "/breb",
        data={"key_type": "telefono", "key_value": "3001112233"},
        follow_redirects=True,
    )
    assert resp.status_code == 200

    client.get("/logout", follow_redirects=True)
    client.post(
        "/login",
        data={"username": "alice", "password": "secret1"},
        follow_redirects=True,
    )
    client.post(
        "/breb",
        data={"key_type": "email", "key_value": "alice@correo.com"},
        follow_redirects=True,
    )
    resp = client.post(
        "/transfer",
        data={"receiver_breb": "3001112233", "amount": "25000", "note": "demo"},
        follow_redirects=True,
    )
    assert resp.status_code == 200
    assert b"completada" in resp.data or b"firmada" in resp.data

    alice = db.fetch_one("SELECT balance FROM users WHERE username = 'alice'")
    bob = db.fetch_one("SELECT balance FROM users WHERE username = 'bob'")
    assert abs(alice["balance"] - 975000.0) < 0.01
    assert abs(bob["balance"] - 1025000.0) < 0.01

    tx = db.fetch_one("SELECT * FROM transactions ORDER BY id DESC LIMIT 1")
    assert client.get(f"/transaction/{tx['id']}").status_code == 200

    ok = client.post(f"/api/verify/{tx['id']}", json={"tamper": False}).get_json()
    bad = client.post(f"/api/verify/{tx['id']}", json={"tamper": True}).get_json()
    assert ok["valid"] is True
    assert bad["valid"] is False

    client.get("/logout", follow_redirects=True)
    client.post(
        "/login",
        data={"username": "bob", "password": "secret1"},
        follow_redirects=True,
    )
    detail = client.get(f"/transaction/{tx['id']}")
    assert b"descifrado" in detail.data.lower()

    print("OK E2E Flask — registro, Bre-B, transferencia, firma y tamper")
    print(f"alice={alice['balance']} bob={bob['balance']} tx={tx['id']}")


if __name__ == "__main__":
    main()
