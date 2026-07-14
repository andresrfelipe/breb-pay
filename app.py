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
def inject_globals():
    unread = 0
    if session.get("user_id"):
        row = db.fetch_one(
            "SELECT COUNT(*) AS c FROM notifications WHERE user_id = ? AND is_read = 0",
            (session["user_id"],),
        )
        unread = int(row["c"]) if row else 0
    return {
        "demo_accounts": seed.public_demo_accounts(),
        "demo_password": seed.DEMO_PASSWORD,
        "unread_notifications": unread,
    }


def login_required(view):
    from functools import wraps

    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        # Sesión huérfana: user_id en cookie pero usuario borrado (p. ej. tras resetear la BD)
        user = db.fetch_one("SELECT id FROM users WHERE id = ?", (session["user_id"],))
        if not user:
            session.clear()
            flash("Tu sesión expiró. Vuelve a iniciar sesión.", "error")
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


def money(amount: float) -> str:
    return f"${amount:,.2f}"


def notify(user_id: int, kind: str, title: str, body: str, link: str | None = None) -> None:
    db.execute(
        """
        INSERT INTO notifications (user_id, kind, title, body, link)
        VALUES (?, ?, ?, ?, ?)
        """,
        (user_id, kind, title, body, link),
    )


def primary_breb_for(user_id: int) -> str | None:
    row = db.fetch_one(
        """
        SELECT key_value FROM breb_keys
        WHERE user_id = ? AND is_active = 1
        ORDER BY is_primary DESC, id ASC
        LIMIT 1
        """,
        (user_id,),
    )
    return row["key_value"] if row else None


def execute_signed_transfer(
    sender: dict,
    receiver: dict,
    receiver_breb: str,
    amount: float,
    note: str,
) -> int:
    """Firma, cifra, mueve saldos y registra la TX. Devuelve el id de la transacción."""
    sender_breb = primary_breb_for(sender["id"])
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
    signature = crypto_service.sign_payload(sender["private_key_pem"], order)
    envelope = crypto_service.encrypt_json(receiver["public_key_pem"], order)

    with db.get_connection() as conn:
        conn.execute(
            "UPDATE users SET balance = balance - ? WHERE id = ?",
            (amount, sender["id"]),
        )
        conn.execute(
            "UPDATE users SET balance = balance + ? WHERE id = ?",
            (amount, receiver["id"]),
        )
        cur = conn.execute(
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
        return cur.lastrowid


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
        "SELECT * FROM breb_keys WHERE user_id = ? ORDER BY is_primary DESC, created_at DESC",
        (user["id"],),
    )
    favorites = db.fetch_all(
        """
        SELECT f.*, b.key_type, u.full_name AS owner_name, u.username AS owner_username,
               COALESCE(b.is_active, 0) AS breb_active
        FROM favorites f
        LEFT JOIN breb_keys b ON b.key_value = f.breb_value
        LEFT JOIN users u ON u.id = b.user_id
        WHERE f.user_id = ?
        ORDER BY f.alias ASC
        """,
        (user["id"],),
    )
    incoming_requests = db.fetch_all(
        """
        SELECT pr.*,
               u.full_name AS requester_name,
               u.username AS requester_username
        FROM payment_requests pr
        JOIN users u ON u.id = pr.requester_id
        WHERE pr.payer_id = ? AND pr.status = 'pending'
        ORDER BY pr.created_at DESC
        """,
        (user["id"],),
    )
    incoming_history = db.fetch_all(
        """
        SELECT pr.*,
               u.full_name AS requester_name,
               u.username AS requester_username
        FROM payment_requests pr
        JOIN users u ON u.id = pr.requester_id
        WHERE pr.payer_id = ? AND pr.status != 'pending'
        ORDER BY COALESCE(pr.resolved_at, pr.created_at) DESC
        LIMIT 15
        """,
        (user["id"],),
    )
    outgoing_requests = db.fetch_all(
        """
        SELECT pr.*,
               u.full_name AS payer_name,
               u.username AS payer_username
        FROM payment_requests pr
        JOIN users u ON u.id = pr.payer_id
        WHERE pr.requester_id = ?
        ORDER BY pr.created_at DESC
        LIMIT 20
        """,
        (user["id"],),
    )
    notifications = db.fetch_all(
        """
        SELECT * FROM notifications
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT 30
        """,
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
        favorites=favorites,
        incoming_requests=incoming_requests,
        incoming_history=incoming_history,
        outgoing_requests=outgoing_requests,
        notifications=notifications,
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

    has_primary = db.fetch_one(
        "SELECT id FROM breb_keys WHERE user_id = ? AND is_primary = 1",
        (user["id"],),
    )
    is_primary = 0 if has_primary else 1

    db.execute(
        "INSERT INTO breb_keys (user_id, key_value, key_type, is_primary) VALUES (?, ?, ?, ?)",
        (user["id"], key_value, key_type, is_primary),
    )
    flash(f"Llave Bre-B '{key_value}' creada.", "success")
    return redirect(url_for("dashboard"))


@app.route("/breb/<int:key_id>/toggle", methods=["POST"])
@login_required
def toggle_breb(key_id: int):
    user = current_user()
    key = db.fetch_one("SELECT * FROM breb_keys WHERE id = ? AND user_id = ?", (key_id, user["id"]))
    if not key:
        flash("Llave no encontrada.", "error")
        return redirect(url_for("dashboard"))

    new_active = 0 if key["is_active"] else 1
    if not new_active and key["is_primary"]:
        # Si desactiva la primaria, promociona otra activa
        other = db.fetch_one(
            """
            SELECT id FROM breb_keys
            WHERE user_id = ? AND id != ? AND is_active = 1
            ORDER BY id ASC LIMIT 1
            """,
            (user["id"], key_id),
        )
        with db.get_connection() as conn:
            conn.execute(
                "UPDATE breb_keys SET is_active = 0, is_primary = 0 WHERE id = ?",
                (key_id,),
            )
            if other:
                conn.execute("UPDATE breb_keys SET is_primary = 1 WHERE id = ?", (other["id"],))
            conn.commit()
        flash(f"Llave '{key['key_value']}' desactivada.", "success")
        return redirect(url_for("dashboard"))

    db.execute("UPDATE breb_keys SET is_active = ? WHERE id = ?", (new_active, key_id))
    flash(
        f"Llave '{key['key_value']}' {'activada' if new_active else 'desactivada'}.",
        "success",
    )
    return redirect(url_for("dashboard"))


@app.route("/breb/<int:key_id>/primary", methods=["POST"])
@login_required
def set_primary_breb(key_id: int):
    user = current_user()
    key = db.fetch_one("SELECT * FROM breb_keys WHERE id = ? AND user_id = ?", (key_id, user["id"]))
    if not key:
        flash("Llave no encontrada.", "error")
        return redirect(url_for("dashboard"))
    if not key["is_active"]:
        flash("Activa la llave antes de marcarla como primaria.", "error")
        return redirect(url_for("dashboard"))

    with db.get_connection() as conn:
        conn.execute("UPDATE breb_keys SET is_primary = 0 WHERE user_id = ?", (user["id"],))
        conn.execute("UPDATE breb_keys SET is_primary = 1 WHERE id = ?", (key_id,))
        conn.commit()

    flash(f"'{key['key_value']}' es ahora tu llave Bre-B primaria.", "success")
    return redirect(url_for("dashboard"))


@app.route("/favorites", methods=["POST"])
@login_required
def add_favorite():
    user = current_user()
    breb_value = normalize_breb(request.form.get("breb_value", ""))
    alias = request.form.get("alias", "").strip()[:40]

    if not breb_value or not alias:
        flash("Indica alias y llave Bre-B para el favorito.", "error")
        return redirect(url_for("dashboard"))

    target = db.fetch_one(
        "SELECT * FROM breb_keys WHERE key_value = ? AND is_active = 1",
        (breb_value,),
    )
    if not target:
        flash("Esa llave Bre-B no existe o está inactiva.", "error")
        return redirect(url_for("dashboard"))
    if target["user_id"] == user["id"]:
        flash("No puedes guardar tu propia llave como favorito.", "error")
        return redirect(url_for("dashboard"))

    existing = db.fetch_one(
        "SELECT id FROM favorites WHERE user_id = ? AND breb_value = ?",
        (user["id"], breb_value),
    )
    if existing:
        db.execute(
            "UPDATE favorites SET alias = ? WHERE id = ?",
            (alias, existing["id"]),
        )
        flash(f"Favorito '{alias}' actualizado.", "success")
    else:
        db.execute(
            "INSERT INTO favorites (user_id, breb_value, alias) VALUES (?, ?, ?)",
            (user["id"], breb_value, alias),
        )
        flash(f"Contacto '{alias}' guardado.", "success")
    return redirect(url_for("dashboard"))


@app.route("/favorites/<int:fav_id>/delete", methods=["POST"])
@login_required
def delete_favorite(fav_id: int):
    user = current_user()
    fav = db.fetch_one("SELECT * FROM favorites WHERE id = ? AND user_id = ?", (fav_id, user["id"]))
    if not fav:
        flash("Favorito no encontrado.", "error")
        return redirect(url_for("dashboard"))
    db.execute("DELETE FROM favorites WHERE id = ?", (fav_id,))
    flash(f"Contacto '{fav['alias']}' eliminado.", "success")
    return redirect(url_for("dashboard"))


@app.route("/transfer", methods=["POST"])
@login_required
def transfer():
    user = current_user()
    receiver_breb = normalize_breb(request.form.get("receiver_breb", ""))
    amount_raw = request.form.get("amount", "").strip()
    note = request.form.get("note", "").strip()[:120]
    confirm_password = request.form.get("confirm_password", "")
    save_alias = request.form.get("save_alias", "").strip()[:40]

    try:
        amount = float(amount_raw)
    except ValueError:
        flash("Monto inválido.", "error")
        return redirect(url_for("dashboard"))

    if amount <= 0:
        flash("El monto debe ser mayor a cero.", "error")
        return redirect(url_for("dashboard"))

    sender = db.fetch_one("SELECT * FROM users WHERE id = ?", (user["id"],))
    if not confirm_password or not check_password_hash(sender["password_hash"], confirm_password):
        flash("Confirmación requerida: reingresa tu contraseña para firmar la transferencia.", "error")
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

    receiver = db.fetch_one("SELECT * FROM users WHERE id = ?", (breb["user_id"],))

    if sender["balance"] < amount:
        flash("Saldo insuficiente.", "error")
        return redirect(url_for("dashboard"))

    tx_id = execute_signed_transfer(sender, receiver, receiver_breb, amount, note)

    if save_alias:
        existing = db.fetch_one(
            "SELECT id FROM favorites WHERE user_id = ? AND breb_value = ?",
            (sender["id"], receiver_breb),
        )
        if existing:
            db.execute("UPDATE favorites SET alias = ? WHERE id = ?", (save_alias, existing["id"]))
        else:
            db.execute(
                "INSERT INTO favorites (user_id, breb_value, alias) VALUES (?, ?, ?)",
                (sender["id"], receiver_breb, save_alias),
            )

    notify(
        receiver["id"],
        "transfer_in",
        "Dinero recibido",
        f"Recibiste {money(amount)} de {sender['full_name']} (@{sender['username']}).",
        url_for("transaction_detail", tx_id=tx_id),
    )
    notify(
        sender["id"],
        "transfer_out",
        "Dinero enviado",
        f"Enviaste {money(amount)} a {receiver['full_name']} ({receiver_breb}).",
        url_for("transaction_detail", tx_id=tx_id),
    )

    flash(
        f"Dinero enviado a {receiver['full_name']} · {money(amount)} COP",
        "success",
    )
    return redirect(url_for("dashboard"))


@app.route("/requests", methods=["POST"])
@login_required
def create_payment_request():
    user = current_user()
    payer_breb = normalize_breb(request.form.get("payer_breb", ""))
    note = request.form.get("note", "").strip()[:120]
    amount_raw = request.form.get("amount", "").strip()

    try:
        amount = float(amount_raw)
    except ValueError:
        flash("Monto inválido en la solicitud.", "error")
        return redirect(url_for("dashboard"))

    if amount <= 0:
        flash("El monto de la solicitud debe ser mayor a cero.", "error")
        return redirect(url_for("dashboard"))

    breb = db.fetch_one(
        "SELECT * FROM breb_keys WHERE key_value = ? AND is_active = 1",
        (payer_breb,),
    )
    if not breb:
        flash("Llave Bre-B del pagador no encontrada.", "error")
        return redirect(url_for("dashboard"))
    if breb["user_id"] == user["id"]:
        flash("No puedes solicitarte un pago a ti mismo.", "error")
        return redirect(url_for("dashboard"))

    req_id = db.execute(
        """
        INSERT INTO payment_requests (
            requester_id, payer_id, payer_breb, requester_breb, amount, note, status
        ) VALUES (?, ?, ?, ?, ?, ?, 'pending')
        """,
        (
            user["id"],
            breb["user_id"],
            payer_breb,
            primary_breb_for(user["id"]),
            round(amount, 2),
            note,
        ),
    )

    notify(
        breb["user_id"],
        "request_in",
        "Nueva solicitud de pago",
        f"{user['full_name']} te solicita {money(amount)} vía Bre-B.",
        url_for("dashboard") + f"#req-{req_id}",
    )
    flash(f"Solicitud de {money(amount)} enviada a '{payer_breb}'.", "success")
    return redirect(url_for("dashboard"))


@app.route("/requests/<int:req_id>/pay", methods=["POST"])
@login_required
def pay_request(req_id: int):
    user = current_user()
    confirm_password = request.form.get("confirm_password", "")
    pr = db.fetch_one("SELECT * FROM payment_requests WHERE id = ?", (req_id,))
    if not pr or pr["payer_id"] != user["id"] or pr["status"] != "pending":
        flash("Solicitud no disponible.", "error")
        return redirect(url_for("dashboard"))

    payer = db.fetch_one("SELECT * FROM users WHERE id = ?", (user["id"],))
    if not confirm_password or not check_password_hash(payer["password_hash"], confirm_password):
        flash("Confirma tu contraseña para firmar el pago de la solicitud.", "error")
        return redirect(url_for("dashboard"))

    requester = db.fetch_one("SELECT * FROM users WHERE id = ?", (pr["requester_id"],))
    # El pagador envía al solicitante usando la Bre-B del solicitante (o su primaria)
    receiver_breb = pr["requester_breb"] or primary_breb_for(requester["id"])
    if not receiver_breb:
        # fallback: cualquier activa del solicitante
        row = db.fetch_one(
            "SELECT key_value FROM breb_keys WHERE user_id = ? AND is_active = 1 LIMIT 1",
            (requester["id"],),
        )
        receiver_breb = row["key_value"] if row else None

    if not receiver_breb:
        flash("El solicitante no tiene una llave Bre-B activa para recibir.", "error")
        return redirect(url_for("dashboard"))

    if payer["balance"] < pr["amount"]:
        flash("Saldo insuficiente para pagar la solicitud.", "error")
        return redirect(url_for("dashboard"))

    note = pr["note"] or f"pago solicitud #{pr['id']}"
    tx_id = execute_signed_transfer(payer, requester, receiver_breb, pr["amount"], note)

    db.execute(
        """
        UPDATE payment_requests
        SET status = 'paid', paid_tx_id = ?, resolved_at = datetime('now')
        WHERE id = ?
        """,
        (tx_id, req_id),
    )

    notify(
        requester["id"],
        "request_paid",
        "Solicitud pagada",
        f"{payer['full_name']} pagó tu solicitud de {money(pr['amount'])}.",
        url_for("transaction_detail", tx_id=tx_id),
    )
    notify(
        payer["id"],
        "transfer_out",
        "Dinero enviado",
        f"Pagaste {money(pr['amount'])} a {requester['full_name']} (solicitud #{req_id}).",
        url_for("transaction_detail", tx_id=tx_id),
    )

    flash(
        f"Dinero enviado a {requester['full_name']} · {money(pr['amount'])} COP",
        "success",
    )
    return redirect(url_for("dashboard"))


@app.route("/requests/<int:req_id>/reject", methods=["POST"])
@login_required
def reject_request(req_id: int):
    user = current_user()
    pr = db.fetch_one("SELECT * FROM payment_requests WHERE id = ?", (req_id,))
    if not pr or pr["payer_id"] != user["id"] or pr["status"] != "pending":
        flash("Solicitud no disponible.", "error")
        return redirect(url_for("dashboard"))

    db.execute(
        """
        UPDATE payment_requests
        SET status = 'rejected', resolved_at = datetime('now')
        WHERE id = ?
        """,
        (req_id,),
    )
    notify(
        pr["requester_id"],
        "request_rejected",
        "Solicitud rechazada",
        f"{user['full_name']} rechazó tu solicitud de {money(pr['amount'])}.",
        url_for("dashboard") + f"#req-out-{req_id}",
    )
    flash("Solicitud rechazada.", "success")
    return redirect(url_for("dashboard"))


@app.route("/requests/<int:req_id>/cancel", methods=["POST"])
@login_required
def cancel_request(req_id: int):
    user = current_user()
    pr = db.fetch_one("SELECT * FROM payment_requests WHERE id = ?", (req_id,))
    if not pr or pr["requester_id"] != user["id"] or pr["status"] != "pending":
        flash("No puedes cancelar esa solicitud.", "error")
        return redirect(url_for("dashboard"))

    db.execute(
        """
        UPDATE payment_requests
        SET status = 'cancelled', resolved_at = datetime('now')
        WHERE id = ?
        """,
        (req_id,),
    )
    flash("Solicitud cancelada.", "success")
    return redirect(url_for("dashboard"))


@app.route("/notifications/read", methods=["POST"])
@login_required
def mark_notifications_read():
    user = current_user()
    db.execute(
        "UPDATE notifications SET is_read = 1 WHERE user_id = ? AND is_read = 0",
        (user["id"],),
    )
    flash("Avisos marcados como leídos.", "success")
    return redirect(url_for("dashboard") + "#notifications")


@app.route("/notifications/<int:notif_id>/read", methods=["POST"])
@login_required
def mark_one_notification_read(notif_id: int):
    user = current_user()
    db.execute(
        "UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?",
        (notif_id, user["id"]),
    )
    return redirect(url_for("dashboard") + "#notifications")


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
    payload_digest = crypto_service.payload_hash(payload)
    sender_fingerprint = crypto_service.public_key_fingerprint(tx["sender_public_key"])

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

    encryption_ok = bool(tx["encrypted_key"] and tx["nonce"] and tx["ciphertext"])
    if user["id"] == tx["receiver_id"]:
        encryption_ok = encryption_ok and decrypted is not None

    trust_steps = [
        {
            "id": "payload",
            "title": "Payload canónico",
            "detail": "JSON ordenado de la orden de pago (sort_keys).",
            "value": f"{len(json.dumps(payload))} chars · txid {payload.get('txid', '')[:8]}…",
            "ok": True,
        },
        {
            "id": "hash",
            "title": "Hash SHA-256",
            "detail": "Resumen criptográfico del payload canónico.",
            "value": payload_digest,
            "ok": True,
        },
        {
            "id": "sign",
            "title": "Firma RSA-PSS",
            "detail": "Firmado con la clave privada del remitente.",
            "value": f"{tx['signature_b64'][:48]}…",
            "ok": bool(tx["signature_b64"]),
        },
        {
            "id": "verify",
            "title": "Verificación pública",
            "detail": f"Clave pública del remitente · fingerprint {sender_fingerprint}",
            "value": "Firma válida" if signature_ok else "Firma inválida",
            "ok": signature_ok,
        },
        {
            "id": "encrypt",
            "title": "Cifrado híbrido",
            "detail": "RSA-OAEP (clave AES) + AES-256-GCM (payload).",
            "value": (
                "Descifrado OK" if decrypted is not None
                else ("Sobre presente" if encryption_ok else "Sobre incompleto")
            ),
            "ok": encryption_ok,
        },
    ]

    return render_template(
        "transaction.html",
        user=user,
        tx=tx,
        payload=payload,
        signature_ok=signature_ok,
        decrypted=decrypted,
        decrypt_error=decrypt_error,
        trust_steps=trust_steps,
        payload_digest=payload_digest,
        sender_fingerprint=sender_fingerprint,
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
