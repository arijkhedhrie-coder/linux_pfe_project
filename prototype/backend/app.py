import threading
import time
import random
import jwt
import datetime
from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_socketio import SocketIO
from mock_data import gen_ssh_bruteforce, gen_nmap_scan, gen_kpi, gen_report

app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")
SECRET = "proto-secret"
ALERTS = []

@app.post("/api/login")
def login():
    d = request.json
    if d.get("username") == "admin" and d.get("password") == "admin":
        token = jwt.encode(
            {"sub": "admin", "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=8)},
            SECRET, algorithm="HS256"
        )
        return jsonify({"token": token})
    return jsonify({"error": "unauthorized"}), 401

@app.get("/api/kpis")
def kpis():
    return jsonify(gen_kpi())

@app.get("/api/alerts")
def alerts():
    for _ in range(3):
        ALERTS.append(gen_ssh_bruteforce())
    ALERTS.append(gen_nmap_scan())
    return jsonify(ALERTS[-20:])

@app.get("/api/reports")
def reports():
    return jsonify(gen_report())

def emit_loop():
    while True:
        time.sleep(3)
        event = gen_ssh_bruteforce() if random.random() > 0.3 else gen_nmap_scan()
        socketio.emit("new_log", event)

threading.Thread(target=emit_loop, daemon=True).start()

if __name__ == "__main__":
    socketio.run(app, port=8000, debug=True)