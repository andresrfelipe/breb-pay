"""
Bre-Pay — Prototipo de pagos digitales tipo Bre-B
con firma RSA y cifrado híbrido del payload.
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone

from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

import crypto_service
import db
import seed

app = Flask(__name__)
app.secret_key = "breb-pay-mvp-dev-secret-change-in-production"

INITIAL_BALANCE = 1_000_000.0
BREB_TYPES = {"telefono", "email", "documento", "alfanumerica"}


@app.context_processor
def inject_demo_accounts():
    return {"demo_accounts": seed.public_demo_accounts(), "demo_password": seed.DEMO_PASSWORD}


def login_required(view):
    from functools import wraps

    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def current_user() -> dict | None:
    if "user_id" not in session:
        return None
    return db.fetch_one(
        "SELECT id, username, full_name, public_key_pem, balance, created_at FROM users WHERE id = ?",
        (session["user_id"],),
    )


def normalize_breb(value: str) -> str:
    return value.strip().lower()


_seeded = False


@app.before_request
def ensure_db():
    global _seeded
    db.init_db()
    if not _seeded:
        seed.seed_demo_users()
        _seeded = True


@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return render_template("index.html", landing=True)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    username = request.form.get("username", "").strip().lower()
    full_name = request.form.get("full_name", "").strip()
    password = request.form.get("password", "")

    if not username or not full_name or len(password) < 6:
        flash("Completa todos los campos. La contraseña debe tener al menos 6 caracteres.", "error")
        return render_template("register.html")

    if not re.fullmatch(r"[a-z0-9_]{3,30}", username):
        flash("Usuario inválido: solo letras minúsculas, números y guion bajo (3-30).", "error")
        return render_template("register.html")

    if db.fetch_one("SELECT id FROM users WHERE username = ?", (username,)):
        flash("Ese nombre de usuario ya existe.", "error")
        return render_template("register.html")

    private_pem, public_pem = crypto_service.generate_rsa_keypair()
    user_id = db.execute(
        """
        INSERT INTO users (username, password_hash, full_name, private_key_pem, public_key_pem, balance)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            username,
            generate_password_hash(password),
            full_name,
            private_pem,
            public_pem,
            INITIAL_BALANCE,
        ),
    )

    session["user_id"] = user_id
    flash("Cuenta creada. Se generó tu par de claves RSA automáticamente.", "success")
    return redirect(url_for("dashboard"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        preset = request.args.get("u", "").strip().lower()
        return render_template("login.html", preset_username=preset)

    username = request.form.get("username", "").strip().lower()
    password = request.form.get("password", "")
    user = db.fetch_one("SELECT * FROM users WHERE username = ?", (username,))

    if not user or not check_password_hash(user["password_hash"], password):
        flash("Credenciales incorrectas.", "error")
        return render_template("login.html", preset_username=username)

    session["user_id"] = user["id"]
    flash(f"Bienvenido, {user['full_name']}.", "success")
    return redirect(url_for("dashboard"))


@app.route("/logout")
def logout():
    session.clear()
    flash("Sesión cerrada.", "success")
    return redirect(url_for("index"))


@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    keys = db.fetch_all(
        "SELECT * FROM breb_keys WHERE user_id = ? ORDER BY created_at DESC",
        (user["id"],),
    )
    txs = db.fetch_all(
        """
        SELECT t.*,
               s.username AS sender_username,
               r.username AS receiver_username
        FROM transactions t
        JOIN users s ON s.id = t.sender_id
        JOIN users r ON r.id = t.receiver_id
        WHERE t.sender_id = ? OR t.receiver_id = ?
        ORDER BY t.created_at DESC
        LIMIT 50
        """,
        (user["id"], user["id"]),
    )
    return render_template(
        "dashboard.html",
        user=user,
        keys=keys,
        transactions=txs,
        breb_types=sorted(BREB_TYPES),
    )


@app.route("/breb", methods=["POST"])
@login_required
def create_breb():
    user = current_user()
    key_type = request.form.get("key_type", "").strip().lower()
    key_value = normalize_breb(request.form.get("key_value", ""))

    if key_type not in BREB_TYPES or not key_value:
        flash("Tipo o valor de llave Bre-B inválido.", "error")
        return redirect(url_for("dashboard"))

    if len(key_value) < 3 or len(key_value) > 80:
        flash("La llave Bre-B debe tener entre 3 y 80 caracteres.", "error")
        return redirect(url_for("dashboard"))

    if db.fetch_one("SELECT id FROM breb_keys WHERE key_value = ?", (key_value,)):
        flash("Esa llave Bre-B ya está registrada.", "error")
        return redirect(url_for("dashboard"))

    db.execute(
        "INSERT INTO breb_keys (user_id, key_value, key_type) VALUES (?, ?, ?)",
        (user["id"], key_value, key_type),
    )
    flash(f"Llave Bre-B '{key_value}' creada.", "success")
    return redirect(url_for("dashboard"))


@app.route("/transfer", methods=["POST"])
@login_required
def transfer():
    user = current_user()
    receiver_breb = normalize_breb(request.form.get("receiver_breb", ""))
    amount_raw = request.form.get("amount", "").strip()
    note = request.form.get("note", "").strip()[:120]

    try:
        amount = float(amount_raw)
    except ValueError:
        flash("Monto inválido.", "error")
        return redirect(url_for("dashboard"))

    if amount <= 0:
        flash("El monto debe ser mayor a cero.", "error")
        return redirect(url_for("dashboard"))

    breb = db.fetch_one(
        "SELECT * FROM breb_keys WHERE key_value = ? AND is_active = 1",
        (receiver_breb,),
    )
    if not breb:
        flash("Llave Bre-B de destino no encontrada.", "error")
        return redirect(url_for("dashboard"))

    if breb["user_id"] == user["id"]:
        flash("No puedes transferirte a ti mismo.", "error")
        return redirect(url_for("dashboard"))

    sender = db.fetch_one("SELECT * FROM users WHERE id = ?", (user["id"],))
    receiver = db.fetch_one("SELECT * FROM users WHERE id = ?", (breb["user_id"],))

    if sender["balance"] < amount:
        flash("Saldo insuficiente.", "error")
        return redirect(url_for("dashboard"))

    sender_breb_row = db.fetch_one(
        "SELECT key_value FROM breb_keys WHERE user_id = ? AND is_active = 1 ORDER BY id LIMIT 1",
        (sender["id"],),
    )
    sender_breb = sender_breb_row["key_value"] if sender_breb_row else None

    order = {
        "txid": str(uuid.uuid4()),
        "sender_id": sender["id"],
        "sender_username": sender["username"],
        "receiver_id": receiver["id"],
        "receiver_username": receiver["username"],
        "receiver_breb": receiver_breb,
        "sender_breb": sender_breb,
        "amount": round(amount, 2),
        "currency": "COP",
        "note": note,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    # 1) Firma digital con la privada del remitente (autenticidad, integridad, no repudio)
    signature = crypto_service.sign_payload(sender["private_key_pem"], order)

    # 2) Cifrado híbrido para el destinatario (confidencialidad del detalle)
    envelope = crypto_service.encrypt_json(receiver["public_key_pem"], order)

    # Actualizar saldos y registrar
    with db.get_connection() as conn:
        conn.execute(
            "UPDATE users SET balance = balance - ? WHERE id = ?",
            (amount, sender["id"]),
        )
        conn.execute(
            "UPDATE users SET balance = balance + ? WHERE id = ?",
            (amount, receiver["id"]),
        )
        conn.execute(
            """
            INSERT INTO transactions (
                sender_id, receiver_id, amount, sender_breb, receiver_breb,
                payload_json, signature_b64, encrypted_key, nonce, ciphertext, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'completed')
            """,
            (
                sender["id"],
                receiver["id"],
                amount,
                sender_breb,
                receiver_breb,
                json.dumps(order, ensure_ascii=False),
                signature,
                envelope["encrypted_key"],
                envelope["nonce"],
                envelope["ciphertext"],
            ),
        )
        conn.commit()

    flash(
        f"Transferencia de ${amount:,.2f} a '{receiver_breb}' completada, firmada y cifrada.",
        "success",
    )
    return redirect(url_for("dashboard"))


@app.route("/transaction/<int:tx_id>")
@login_required
def transaction_detail(tx_id: int):
    user = current_user()
    tx = db.fetch_one(
        """
        SELECT t.*,
               s.username AS sender_username,
               s.public_key_pem AS sender_public_key,
               r.username AS receiver_username
        FROM transactions t
        JOIN users s ON s.id = t.sender_id
        JOIN users r ON r.id = t.receiver_id
        WHERE t.id = ?
        """,
        (tx_id,),
    )
    if not tx:
        flash("Transacción no encontrada.", "error")
        return redirect(url_for("dashboard"))

    if user["id"] not in (tx["sender_id"], tx["receiver_id"]):
        flash("No tienes permiso para ver esta transacción.", "error")
        return redirect(url_for("dashboard"))

    payload = json.loads(tx["payload_json"])
    signature_ok = crypto_service.verify_signature(
        tx["sender_public_key"], payload, tx["signature_b64"]
    )

    decrypted = None
    decrypt_error = None
    if user["id"] == tx["receiver_id"]:
        full_user = db.fetch_one("SELECT private_key_pem FROM users WHERE id = ?", (user["id"],))
        try:
            decrypted = crypto_service.decrypt_json(
                full_user["private_key_pem"],
                {
                    "encrypted_key": tx["encrypted_key"],
                    "nonce": tx["nonce"],
                    "ciphertext": tx["ciphertext"],
                },
            )
        except Exception as exc:
            decrypt_error = str(exc)

    return render_template(
        "transaction.html",
        user=user,
        tx=tx,
        payload=payload,
        signature_ok=signature_ok,
        decrypted=decrypted,
        decrypt_error=decrypt_error,
    )


@app.route("/api/verify/<int:tx_id>", methods=["POST"])
@login_required
def api_verify(tx_id: int):
    """Endpoint para demo: verifica firma o prueba un payload alterado."""
    user = current_user()
    tx = db.fetch_one(
        """
        SELECT t.*, s.public_key_pem AS sender_public_key
        FROM transactions t
        JOIN users s ON s.id = t.sender_id
        WHERE t.id = ?
        """,
        (tx_id,),
    )
    if not tx or user["id"] not in (tx["sender_id"], tx["receiver_id"]):
        return jsonify({"ok": False, "error": "No autorizado"}), 403

    body = request.get_json(silent=True) or {}
    tamper = bool(body.get("tamper", False))
    payload = json.loads(tx["payload_json"])

    if tamper:
        payload = dict(payload)
        payload["amount"] = float(payload["amount"]) + 999999

    valid = crypto_service.verify_signature(
        tx["sender_public_key"], payload, tx["signature_b64"]
    )
    return jsonify(
        {
            "ok": True,
            "valid": valid,
            "tampered": tamper,
            "message": (
                "Firma inválida: el payload fue alterado."
                if tamper and not valid
                else ("Firma válida." if valid else "Firma inválida.")
            ),
            "payload_checked": payload,
        }
    )


@app.route("/api/lookup-breb")
@login_required
def lookup_breb():
    value = normalize_breb(request.args.get("q", ""))
    if not value:
        return jsonify({"found": False})
    row = db.fetch_one(
        """
        SELECT b.key_value, b.key_type, u.username, u.full_name
        FROM breb_keys b
        JOIN users u ON u.id = b.user_id
        WHERE b.key_value = ? AND b.is_active = 1
        """,
        (value,),
    )
    if not row:
        return jsonify({"found": False})
    return jsonify({"found": True, "key": dict(row)})


if __name__ == "__main__":
    db.init_db()
    app.run(debug=True, port=5000)
