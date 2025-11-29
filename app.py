import os
import json
import requests
import bcrypt
import base64
import time
import uuid
from flask import Flask, request, jsonify, send_file, send_from_directory
# Hanya impor firestore, menghapus storage karena tidak dipakai
from firebase_admin import credentials, firestore, initialize_app 
from io import BytesIO
from functools import wraps
from dotenv import load_dotenv
# Impor yang dikurangi sesuai permintaan
from utils import make_signature, verify_signature, create_jwt, decode_jwt
from pdf_ticket import generate_ticket_pdf 

# ---------------- ENV CONFIG ----------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(dotenv_path=os.path.join(BASE_DIR, 'config.example.env'))

API_SIGNATURE_SECRET = os.getenv('API_SIGNATURE_SECRET', 'supersecret')
JWT_SECRET = os.getenv('JWT_SECRET', 'jwtsecret')
PUBLIC_API_PRIMARY = os.getenv('PUBLIC_API_PRIMARY')
PUBLIC_API_FALLBACK = os.getenv('PUBLIC_API_FALLBACK')
FONNTE_TOKEN = os.getenv('FONNTE_TOKEN', 'YOUR_FONNTE_TOKEN')

# Firebase config
FIREBASE_SERVICE_ACCOUNT = os.getenv('FIREBASE_SERVICE_ACCOUNT')

# ---------------- FIREBASE INIT (Firestore only) ----------------
firebase_initialized = False
try:
    if FIREBASE_SERVICE_ACCOUNT:
        # PERBAIKAN KRITIS: Mendeteksi apakah nilai adalah string JSON (Railway) atau path file (Lokal)
        if FIREBASE_SERVICE_ACCOUNT.startswith('{'):
            # Memuat string JSON dari environment variable (untuk cloud deployment)
            cred = credentials.Certificate(json.loads(FIREBASE_SERVICE_ACCOUNT))
            print("✅ Firebase initialized using JSON string (Cloud/Railway).")
        else:
            # Asumsi path file lokal
            cred = credentials.Certificate(os.path.join(BASE_DIR, FIREBASE_SERVICE_ACCOUNT))
            print("✅ Firebase initialized using local file path.")
            
        initialize_app(cred)
        db = firestore.client()
        firebase_initialized = True
        print("✅ Firebase initialized (Firestore only).")
except Exception as e:
    print("⚠️ Firebase init failed:", e)
    firebase_initialized = False

FRONTEND_DIR = os.path.join(BASE_DIR, '..', 'frontend')

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path='')
app.secret_key = os.urandom(24)

# ---------------- TICKET STORAGE ----------------
TICKET_DIR = os.path.join(BASE_DIR, "tickets")
os.makedirs(TICKET_DIR, exist_ok=True)

# ---------------- UTILITIES ----------------
def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def check_password(password: str, hashed: bytes) -> bool:
    return bcrypt.checkpw(password.encode(), hashed)

def get_user_by_email(email):
    try:
        if 'db' not in globals():
            return None
        doc = db.collection('users').document(email).get()
        return doc.to_dict() if doc.exists else None
    except Exception:
        return None

def fetch_events():
    try:
        if 'db' in globals():
            events_docs = db.collection('events').stream()
            events = [d.to_dict() for d in events_docs]
            if events:
                return events
    except Exception as e:
        print("Firestore events fetch error:", e)

    # Fallback HTTP API
    for api_url in [PUBLIC_API_PRIMARY, PUBLIC_API_FALLBACK]:
        try:
            resp = requests.get(api_url, timeout=3)
            if resp.ok:
                return resp.json()
        except Exception as e:
            print("Public API error:", e)

    return []

# ---------------- AUTH ROUTES ----------------
@app.route('/')
def serve_index():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/login')
def serve_login():
    return send_from_directory(app.static_folder, 'login.html')

@app.route('/signup')
def serve_signup():
    return send_from_directory(app.static_folder, 'signup.html')

@app.route('/dashboard')
def serve_dashboard():
    return send_from_directory(app.static_folder, 'dashboard.html')

@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    username = data.get('username', email.split('@')[0])

    if not email or not password:
        return jsonify({'error': 'missing fields'}), 400

    if get_user_by_email(email):
        return jsonify({'error': 'user exists'}), 400

    hashed = hash_password(password)
    user_doc = {
        'email': email,
        'username': username,
        'password': hashed.decode('utf-8'),
        'created_at': firestore.SERVER_TIMESTAMP if firebase_initialized else time.time()
    }

    if firebase_initialized:
        db.collection('users').document(email).set(user_doc)

    return jsonify({
        'token': create_jwt({'email': email, 'username': username}, JWT_SECRET)
    }), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    user = get_user_by_email(email)
    if not user:
        return jsonify({'error': 'invalid credentials'}), 401

    stored = user['password']
    try:
        ok = bcrypt.checkpw(password.encode(), stored.encode())
    except Exception:
        ok = (password == stored)

    if not ok:
        return jsonify({'error': 'invalid credentials'}), 401

    token = create_jwt({'email': email, 'username': user.get('username')}, JWT_SECRET)
    return jsonify({'token': token}), 200

def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get('Authorization', '')
        if not auth.startswith('Bearer '):
            return jsonify({'error': 'missing token'}), 401
        token = auth.split(' ', 1)[1]
        data = decode_jwt(token, JWT_SECRET)
        if not data:
            return jsonify({'error': 'invalid token'}), 401
        request.user = data
        return f(*args, **kwargs)
    return wrapper

# ---------------- SEND TICKET TEXT ONLY ----------------
@app.route('/api/tickets/send', methods=['POST'])
def send_ticket():
    order = request.get_json()
    print("📦 DEBUG ORDER:", order)

    if not order:
        return jsonify({'error': 'Invalid JSON payload'}), 400

    whatsapp = order.get('whatsapp')
    if not whatsapp:
        return jsonify({'error': 'Nomor WhatsApp belum diisi'}), 400

    # Build text message
    message_template = f"""
✅ E-Ticket Konser Berhasil Dipesan!

Halo {order.get('username', 'Pengguna')}, ini detail pesanan tiket Anda:

Event: {order.get('event_name', '-')}
Tanggal: {order.get('date', '-')}
Jumlah Tiket: {order.get('quantity', '-')}
Total Harga: Rp {order.get('price', '-')}
ID Pesanan: {order.get('id', '-')}

*Catatan: Tiket fisik akan diambil di lokasi acara dengan menunjukkan ID Pesanan ini.*
""".strip()

    fonnte_url = "https://api.fonnte.com/send"
    headers = {"Authorization": FONNTE_TOKEN} if FONNTE_TOKEN else {}

    payload = {
        "target": whatsapp,
        "message": message_template
    }

    try:
        resp = requests.post(fonnte_url, headers=headers, data=payload, timeout=30)

        if resp.ok:
            fonnte_json = resp.json()
            if fonnte_json.get('status') is True:
                print("✅ Fonnte text message sent successfully.")
                return jsonify({"status": "success", "message": "Tiket berhasil dikirim ke WhatsApp (Teks).", "details": fonnte_json}), 200
            else:
                print("🛑 Fonnte responded OK but status false:", resp.text)
                return jsonify({"status": "error", "message": "Gagal mengirim pesan (Fonnte error).", "details": fonnte_json}), 500
        else:
            print("🛑 Fonnte HTTP Error:", resp.status_code, resp.text)
            return jsonify({"status": "error", "message": f"Gagal mengirim pesan (HTTP {resp.status_code})."}), 500

    except Exception as e:
        import traceback
        print("❌ ERROR /api/tickets/send:", traceback.format_exc())
        return jsonify({"status": "error", "message": f"Terjadi kesalahan koneksi: {str(e)}"}), 500

# ---------------- CANCEL TICKET ----------------
@app.route('/api/tickets/<order_id>/cancel', methods=['POST'])
@require_auth
def cancel_ticket(order_id):

    if 'db' not in globals():
        return jsonify({'error': 'Database not initialized'}), 500

    docref = db.collection('orders').document(order_id)
    doc = docref.get()

    if not doc.exists:
        return jsonify({'error': 'not found'}), 404

    order = doc.to_dict()

    if order['user_email'] != request.user['email']:
        return jsonify({'error': 'forbidden'}), 403

    if order.get('status') != 'paid':
        return jsonify({'error': 'cannot cancel'}), 400

    docref.update({'status': 'cancelled'})
    return jsonify({'message': 'cancelled'}), 200

# ---------------- DOWNLOAD PDF ----------------
@app.route('/api/tickets/<order_id>/pdf', methods=['GET'])
@require_auth
def download_ticket_pdf(order_id):
    if 'db' not in globals():
        return jsonify({'error': 'Database not initialized'}), 500

    doc = db.collection('orders').document(order_id).get()
    if not doc.exists:
        return jsonify({'error': 'not found'}), 404

    order = doc.to_dict()
    if order['user_email'] != request.user['email']:
        return jsonify({'error': 'forbidden'}), 403

    pdf_bytes = generate_ticket_pdf(order)
    return send_file(BytesIO(pdf_bytes),
                     mimetype='application/pdf',
                     as_attachment=True,
                     download_name=f"ticket_{order_id}.pdf")

# ---------------- EVENTS LIST ----------------
@app.route('/api/events', methods=['GET'])
def events():
    ev = fetch_events()
    return jsonify(ev), 200

# ---------------- HISTORY ----------------
@app.route('/api/history', methods=['GET'])
@require_auth
def history():
    email = request.user['email']
    try:
        if 'db' not in globals():
            return jsonify({'tickets': []}), 200

        orders = [d.to_dict() for d in db.collection('orders').where('user_email', '==', email).stream()]
    except Exception:
        orders = []
    return jsonify({'tickets': orders}), 200

# ---------------- MAIN ----------------
if __name__ == '__main__':
    app.run(debug=True, port=5000, use_reloader=False)
