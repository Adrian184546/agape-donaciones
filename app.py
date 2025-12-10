import os
import sqlite3
import secrets
import urllib.parse
from datetime import datetime
from functools import wraps

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    send_from_directory,
    abort,
    session,
)
import qrcode

# ------------------------
# CONFIGURACIÓN BÁSICA
# ------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "donations.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
QR_FOLDER = os.path.join(BASE_DIR, "static", "qr")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(QR_FOLDER, exist_ok=True)

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB
app.config["SECRET_KEY"] = "cambiame_esta_clave_por_una_mas_larga_y_segura"


# ------------------------
# DECORADORES DE AUTENTICACIÓN
# ------------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return decorated_function


def role_required(role):
    """Permite solo a usuarios con cierto rol (ej: 'admin')."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if session.get("role") != role:
                return "No tenés permisos para esta acción", 403
            return f(*args, **kwargs)
        return wrapper
    return decorator


@app.context_processor
def inject_user_context():
    """Hace disponible info de sesión en todos los templates."""
    return {
        "logged_in": session.get("logged_in", False),
        "current_user": {
            "username": session.get("username"),
            "role": session.get("role"),
        },
    }


# ------------------------
# BASE DE DATOS
# ------------------------
def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Crea tablas si no existen y usuario admin por defecto."""
    conn = get_db_connection()
    cur = conn.cursor()

    # Tabla donaciones
    cur.execute("""
        CREATE TABLE IF NOT EXISTS donations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            donor_name TEXT NOT NULL,
            donor_phone TEXT,
            donor_email TEXT,
            donation_type TEXT,
            quantity INTEGER,
            destination TEXT,
            created_at TEXT,
            status TEXT,
            token TEXT UNIQUE,
            photo_path TEXT
        );
    """)

    # Tabla usuarios
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT
        );
    """)

    # Crear usuario admin por defecto si no existe
    cur.execute("SELECT * FROM users WHERE username = 'admin'")
    if cur.fetchone() is None:
        cur.execute("""
            INSERT INTO users (username, password, role)
            VALUES ('admin', 'agape2025', 'admin')
        """)

    conn.commit()
    conn.close()


# ------------------------
# FUNCIONES AUXILIARES
# ------------------------
def generate_token():
    """Token público para seguimiento."""
    return secrets.token_urlsafe(12)


def generate_qr_for_token(token: str) -> str:
    """Genera un QR que apunta a la URL pública de seguimiento."""
    track_url = url_for("track_donation", token=token, _external=True)
    img = qrcode.make(track_url)
    filename = f"qr_{token}.png"
    filepath = os.path.join(QR_FOLDER, filename)
    img.save(filepath)
    return filename


# ------------------------
# LOGIN / LOGOUT
# ------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        conn = get_db_connection()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ? AND password = ?",
            (username, password),
        ).fetchone()
        conn.close()

        if user:
            session["logged_in"] = True
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]

            next_url = request.args.get("next") or url_for("admin_list")
            return redirect(next_url)
        else:
            error = "Usuario o contraseña incorrectos."
            return render_template("login.html", error=error)

    return render_template("login.html", error=None)


@app.route("/logout")
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))


# ------------------------
# RUTAS PRINCIPALES (PANEL)
# ------------------------
@app.route("/")
@login_required
def admin_list():
    """
    Panel de administración:
    lista donaciones con buscador y filtro por estado.
    """
    q = request.args.get("q", "").strip()
    status_filter = request.args.get("status", "").strip()

    conn = get_db_connection()
    sql = "SELECT * FROM donations WHERE 1=1"
    params = []

    if q:
        like = f"%{q}%"
        sql += """
            AND (
                donor_name   LIKE ?
                OR donor_phone   LIKE ?
                OR donor_email   LIKE ?
                OR donation_type LIKE ?
                OR destination   LIKE ?
                OR token         LIKE ?
            )
        """
        params.extend([like, like, like, like, like, like])

    if status_filter:
        sql += " AND status = ?"
        params.append(status_filter)

    sql += " ORDER BY created_at DESC"

    donations = conn.execute(sql, params).fetchall()
    conn.close()

    return render_template(
        "admin_list.html",
        donations=donations,
        q=q,
        status_filter=status_filter,
    )


@app.route("/new", methods=["GET", "POST"])
@login_required
def new_donation():
    """
    Formulario para registrar una nueva donación.
    """
    if request.method == "POST":
        donor_name = request.form.get("donor_name")
        donor_phone = request.form.get("donor_phone")
        donor_email = request.form.get("donor_email")
        donation_type = request.form.get("donation_type")
        quantity = request.form.get("quantity") or 0
        destination = request.form.get("destination")
        created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        status = "Registrada"
        token = generate_token()

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO donations
            (donor_name, donor_phone, donor_email, donation_type, quantity,
             destination, created_at, status, token, photo_path)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                donor_name,
                donor_phone,
                donor_email,
                donation_type,
                quantity,
                destination,
                created_at,
                status,
                token,
                None,
            ),
        )
        conn.commit()
        conn.close()

        # Luego de crear, generamos el QR
        generate_qr_for_token(token)

        return redirect(url_for("donation_qr", token=token))

    return render_template("new_donation.html")


@app.route("/donation/<token>/qr")
@login_required
def donation_qr(token):
    """
    Página para ver el QR y datos básicos (para impresión).
    """
    conn = get_db_connection()
    donation = conn.execute(
        "SELECT * FROM donations WHERE token = ?", (token,)
    ).fetchone()
    conn.close()

    if donation is None:
        abort(404)

    qr_filename = f"qr_{token}.png"
    qr_path = os.path.join(QR_FOLDER, qr_filename)
    if not os.path.exists(qr_path):
        generate_qr_for_token(token)

    track_url = url_for("track_donation", token=token, _external=True)

    return render_template(
        "donation_qr.html",
        donation=donation,
        qr_filename=qr_filename,
        track_url=track_url,
    )


@app.route("/donation/<token>/print")
@login_required
def donation_print(token):
    """
    Versión especial para IMPRIMIR ticket tipo POS con QR.
    """
    conn = get_db_connection()
    donation = conn.execute(
        "SELECT * FROM donations WHERE token = ?", (token,)
    ).fetchone()
    conn.close()

    if donation is None:
        abort(404)

    qr_filename = f"qr_{token}.png"
    qr_path = os.path.join(QR_FOLDER, qr_filename)
    if not os.path.exists(qr_path):
        generate_qr_for_token(token)

    track_url = url_for("track_donation", token=token, _external=True)

    return render_template(
        "donation_print.html",
        donation=donation,
        qr_filename=qr_filename,
        track_url=track_url,
    )


# ------------------------
# RUTA PÚBLICA (DONANTE)
# ------------------------
@app.route("/track/<token>")
def track_donation(token):
    """
    Página pública que ve el donante al escanear el QR.
    Muestra el estado y, si está entregada y con foto, la foto.
    También permite compartir el enlace por WhatsApp.
    """
    conn = get_db_connection()
    donation = conn.execute(
        "SELECT * FROM donations WHERE token = ?", (token,)
    ).fetchone()
    conn.close()

    if donation is None:
        abort(404)

    # URL completa de esta página (para compartir)
    track_url = url_for("track_donation", token=token, _external=True)

    # Texto que se va a mandar por WhatsApp
    share_text = f"Te comparto el seguimiento de esta donación de Ágape en acción: {track_url}"

    # Link oficial de WhatsApp con el texto ya codificado
    whatsapp_url = "https://wa.me/?text=" + urllib.parse.quote(share_text)

    return render_template(
        "track.html",
        donation=donation,
        track_url=track_url,
        whatsapp_url=whatsapp_url,
    )


# ------------------------
# ACTUALIZAR DONACIÓN
# ------------------------
@app.route("/admin/update/<int:donation_id>", methods=["GET", "POST"])
@login_required
def update_donation(donation_id):
    """
    Pantalla para actualizar:
    - Estado y foto SIEMPRE.
    - Datos de la donación SOLO cuando está en estado 'Registrada'.
    """
    conn = get_db_connection()
    donation = conn.execute(
        "SELECT * FROM donations WHERE id = ?", (donation_id,)
    ).fetchone()

    if donation is None:
        conn.close()
        abort(404)

    edit_allowed = donation["status"] == "Registrada"

    if request.method == "POST":
        new_status = request.form.get("status")
        photo = request.files.get("photo")

        # Valores actuales por defecto
        donor_name = donation["donor_name"]
        donor_phone = donation["donor_phone"]
        donor_email = donation["donor_email"]
        donation_type = donation["donation_type"]
        quantity = donation["quantity"]
        destination = donation["destination"]

        # Si está Registrada, permitimos editar datos
        if edit_allowed:
            donor_name = request.form.get("donor_name")
            donor_phone = request.form.get("donor_phone")
            donor_email = request.form.get("donor_email")
            donation_type = request.form.get("donation_type")
            quantity = request.form.get("quantity") or 0
            destination = request.form.get("destination")

        photo_path = donation["photo_path"]

        # Si hay foto nueva, la guardamos en /static/uploads
        if photo and photo.filename:
            ext = os.path.splitext(photo.filename)[1].lower()
            fname = f"donation_{donation_id}{ext}"
            save_path = os.path.join(UPLOAD_FOLDER, fname)
            photo.save(save_path)
            photo_path = f"uploads/{fname}"

        conn.execute(
            """
            UPDATE donations
            SET donor_name = ?,
                donor_phone = ?,
                donor_email = ?,
                donation_type = ?,
                quantity = ?,
                destination = ?,
                status = ?,
                photo_path = ?
            WHERE id = ?
        """,
            (
                donor_name,
                donor_phone,
                donor_email,
                donation_type,
                quantity,
                destination,
                new_status,
                photo_path,
                donation_id,
            ),
        )
        conn.commit()
        conn.close()

        return redirect(url_for("donation_qr", token=donation["token"]))

    conn.close()
    return render_template(
        "update_donation.html",
        donation=donation,
        edit_allowed=edit_allowed,
    )


# ------------------------
# ELIMINAR DONACIÓN (SOLO ADMIN)
# ------------------------
@app.route("/admin/delete/<int:donation_id>", methods=["POST"])
@login_required
@role_required("admin")
def delete_donation(donation_id):
    """
    Eliminar una donación SOLO si está en estado 'Registrada' y usuario admin.
    """
    conn = get_db_connection()
    donation = conn.execute(
        "SELECT * FROM donations WHERE id = ?", (donation_id,)
    ).fetchone()

    if donation is None:
        conn.close()
        abort(404)

    if donation["status"] != "Registrada":
        conn.close()
        return "Solo se pueden eliminar donaciones en estado 'Registrada'.", 400

    conn.execute("DELETE FROM donations WHERE id = ?", (donation_id,))
    conn.commit()
    conn.close()

    return redirect(url_for("admin_list"))


# ------------------------
# ARCHIVOS SUBIDOS
# ------------------------
@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    """Servir archivos subidos."""
    return send_from_directory(UPLOAD_FOLDER, filename)


# ------------------------
# MAIN
# ------------------------
if __name__ == "__main__":
    init_db()
    app.run(debug=True)
