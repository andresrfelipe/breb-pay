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
    assert b"Bre-B" in resp.data or b"Llaves" in resp.data or b"llave" in resp.data.lower()

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

    fav = client.post(
        "/favorites",
        data={"alias": "Bob", "breb_value": "3001112233"},
        follow_redirects=True,
    )
    assert fav.status_code == 200

    req = client.post(
        "/requests",
        data={"payer_breb": "3001112233", "amount": "10000", "note": "cafe"},
        follow_redirects=True,
    )
    assert req.status_code == 200

    resp = client.post(
        "/transfer",
        data={
            "receiver_breb": "3001112233",
            "amount": "25000",
            "note": "demo",
            "confirm_password": "secret1",
            "save_alias": "Bob pago",
        },
        follow_redirects=True,
    )
    assert resp.status_code == 200
    assert b"Transferencia completada" in resp.data or b"Firma v" in resp.data
    assert b"Payload cifrado" in resp.data
    assert b"Saldos actualizados" in resp.data

    denied = client.post(
        "/transfer",
        data={"receiver_breb": "3001112233", "amount": "100", "note": "no"},
        follow_redirects=True,
    )
    assert b"Confirmaci" in denied.data or b"contrase" in denied.data.lower()

    alice = db.fetch_one("SELECT id, balance FROM users WHERE username = 'alice'")
    bob = db.fetch_one("SELECT id, balance FROM users WHERE username = 'bob'")
    assert abs(alice["balance"] - 975000.0) < 0.01
    assert abs(bob["balance"] - 1025000.0) < 0.01

    tx = db.fetch_one("SELECT * FROM transactions ORDER BY id DESC LIMIT 1")
    detail = client.get(f"/transaction/{tx['id']}")
    assert detail.status_code == 200
    assert b"Cadena de confianza" in detail.data
    assert b"Auditor" in detail.data

    assert client.get("/home").status_code == 200
    assert client.get("/send").status_code == 200
    assert client.get("/keys").status_code == 200
    assert client.get("/security").status_code == 200
    filtered = client.get("/movements?direction=sent&signature=valid")
    assert filtered.status_code == 200

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

    pr = db.fetch_one(
        "SELECT * FROM payment_requests WHERE payer_id = ? AND status = 'pending'",
        (bob["id"],),
    )
    assert pr is not None
    paid = client.post(
        f"/requests/{pr['id']}/pay",
        data={"confirm_password": "secret1"},
        follow_redirects=True,
    )
    assert paid.status_code == 200

    dash = client.get("/home")
    assert b"Centro de avisos" in dash.data

    key = db.fetch_one("SELECT * FROM breb_keys WHERE key_value = '3001112233'")
    toggled = client.post(f"/breb/{key['id']}/toggle", follow_redirects=True)
    assert toggled.status_code == 200

    print("OK E2E — vistas, wizard success, favoritos, solicitudes, filtros")
    print(f"alice={alice['balance']} bob tx={tx['id']}")


if __name__ == "__main__":
    main()
