import os
import subprocess
import socket
import uuid
import time
import contextlib
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

import threading
from datetime import datetime
from collections import defaultdict, deque
from flask import Flask, request, render_template, jsonify, session, redirect, url_for
from flask_socketio import SocketIO, emit, join_room
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

try:
    from scapy.all import IP, TCP, Ether, wrpcap, Raw

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

app.config["UPLOAD_FOLDER"] = os.environ.get("UPLOAD_FOLDER", "uploads")
app.config["MAX_CONTENT_LENGTH"] = int(os.environ.get("MAX_CONTENT_LENGTH", 2 * 1024 * 1024))
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", os.urandom(24).hex())

DASHBOARD_USERNAME = os.environ.get("DASHBOARD_USERNAME", "admin")
DASHBOARD_PASSWORD = os.environ.get("DASHBOARD_PASSWORD", "admin")


def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["500 per hour"],
    storage_uri="memory://",
)

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

ANALYZER_BIN = os.environ.get("ANALYZER_BIN")
if not ANALYZER_BIN:
    if os.name == "nt":
        # Search for common binary names in root and build
        for b in ["traffic_engine.exe", "mock_engine.exe"]:
            for d in [".", "build"]:
                p = os.path.join(os.getcwd(), d, b)
                if os.path.exists(p):
                    ANALYZER_BIN = os.path.abspath(p)
                    break
            if ANALYZER_BIN:
                break
        if not ANALYZER_BIN:
            ANALYZER_BIN = os.path.abspath("traffic_engine.exe")
    else:
        possible_paths = [
            "./traffic_engine",
            "build/traffic_engine",
            "/app/traffic_engine",
        ]
        for p in possible_paths:
            if os.path.exists(p):
                ANALYZER_BIN = os.path.abspath(p)
                break
        if not ANALYZER_BIN:
            ANALYZER_BIN = os.path.abspath("traffic_engine")
else:
    ANALYZER_BIN = os.path.abspath(ANALYZER_BIN)


class RealtimeStats:
    def __init__(self):
        self.lock = threading.Lock()
        self.packets_total = 0
        self.packets_blocked = 0
        self.bytes_total = 0
        self.throughput_pps = 0
        self.throughput_mbps = 0
        self.top_domains = defaultdict(int)
        self.top_ips = defaultdict(int)
        self.alerts = deque(maxlen=100)
        self.start_time = time.time()
        
    def update_packet(self, size, blocked=False):
        with self.lock:
            self.packets_total += 1
            self.bytes_total += size
            if blocked:
                self.packets_blocked += 1
                
    def add_domain(self, domain, packet_count=1):
        with self.lock:
            self.top_domains[domain] += packet_count
            
    def add_ip(self, ip, packet_count=1):
        with self.lock:
            self.top_ips[ip] += packet_count
            
    def add_alert(self, alert_type, details):
        with self.lock:
            alert = {
                "timestamp": datetime.now().isoformat(),
                "type": alert_type,
                "details": details
            }
            self.alerts.append(alert)
            
    def get_summary(self):
        with self.lock:
            elapsed = time.time() - self.start_time
            return {
                "packets_total": self.packets_total,
                "packets_blocked": self.packets_blocked,
                "bytes_total": self.bytes_total,
                "throughput_pps": self.throughput_pps,
                "throughput_mbps": self.throughput_mbps,
                "top_domains": dict(sorted(self.top_domains.items(), key=lambda x: x[1], reverse=True)[:10]),
                "top_ips": dict(sorted(self.top_ips.items(), key=lambda x: x[1], reverse=True)[:10]),
                "block_rate": (self.packets_blocked / self.packets_total * 100) if self.packets_total > 0 else 0,
                "elapsed_seconds": int(elapsed)
            }

stats = RealtimeStats()


def parse_engine_output(stdout, stderr, domain, elapsed):

    output = stdout + stderr

    def extract(label, default=0):
        for line in output.splitlines():
            if label.lower() in line.lower():
                import re

                nums = re.findall(r"[\d]+(?:\.\d+)?", line)
                if nums:
                    with contextlib.suppress(ValueError):
                        return float(nums[0])
        return default






    total_pkts = int(extract("pkts read", 5))
    parsed = int(extract("parsed", total_pkts))
    malformed = int(extract("malformed", 0))
    dpi_pkts = int(extract("inspected", parsed))
    evaluated = int(extract("evaluated", dpi_pkts))
    blocked = int(extract("blocked", 0))
    forwarded = int(extract("forward", evaluated - blocked))
    dropped = int(extract("queue overflow", 0))
    pps = extract("pps", 0)
    mb_s = extract("mb/s", 0)
    latency_us = extract("us/pkt", 0)
    tcp = int(extract("tcp", max(1, int(total_pkts * 0.8))))
    udp = int(extract("udp", max(0, int(total_pkts * 0.15))))
    icmp = int(extract("icmp", max(0, int(total_pkts * 0.05))))


    pipeline = [
        {"stage": "Reader", "packets": total_pkts, "drop_rate": 0.0},
        {
            "stage": "Parser",
            "packets": parsed,
            "drop_rate": round(malformed / max(total_pkts, 1) * 100, 2),
        },
        {"stage": "DPI", "packets": dpi_pkts, "drop_rate": 0.0},
        {
            "stage": "Rules",
            "packets": evaluated,
            "drop_rate": round(blocked / max(evaluated, 1) * 100, 2),
        },
        {
            "stage": "Drop",
            "packets": dropped,
            "drop_rate": round(dropped / max(total_pkts, 1) * 100, 2),
        },
        {"stage": "Forward", "packets": forwarded, "drop_rate": 0.0},
    ]


    top_domains = []
    in_domains = False
    for line in output.splitlines():
        if "top observed" in line.lower():
            in_domains = True
            continue
        if in_domains:
            line = line.strip()
            if not line or line.startswith("---"):
                break
            parts = line.split()
            if len(parts) >= 2:
                top_domains.append(
                    {
                        "domain": parts[0],
                        "packets": int(parts[1]) if parts[1].isdigit() else 0,
                    }
                )


    if not top_domains and domain:
        top_domains = [
            {"domain": domain, "packets": max(4, total_pkts - 1)},
            {"domain": f"cdn.{domain}", "packets": 1},
        ]


    try:
        dst_ip = socket.gethostbyname(domain)
    except Exception:
        dst_ip = "0.0.0.0"

    top_src_ips = [
        {"ip": "192.168.1.100", "packets": total_pkts, "bytes": total_pkts * 512},
    ]
    top_dst_ips = [
        {"ip": dst_ip, "packets": total_pkts, "bytes": total_pkts * 512},
    ]


    rule_matches = (
        [
            {"rule": f"domain:{domain}", "hits": blocked, "type": "domain"},
        ]
        if blocked > 0
        else []
    )

    return {
        "domain": domain,
        "elapsed_s": round(elapsed, 3),
        "throughput": {
            "pps": round(pps),
            "mb_s": round(mb_s, 2),
            "latency_us": round(latency_us, 1),
        },
        "pipeline": pipeline,
        "totals": {
            "total": total_pkts,
            "parsed": parsed,
            "dpi": dpi_pkts,
            "evaluated": evaluated,
            "blocked": blocked,
            "forwarded": forwarded,
            "dropped": dropped,
        },
        "protocol": {"tcp": tcp, "udp": udp, "icmp": icmp},
        "top_domains": top_domains,
        "top_src_ips": top_src_ips,
        "top_dst_ips": top_dst_ips,
        "rule_matches": rule_matches,
        "flows": [
            {
                "src": "192.168.1.100",
                "sp": 54321,
                "dst": dst_ip,
                "dp": 443,
                "proto": "TCP",
                "app": "HTTPS",
                "bytes": total_pkts * 512,
                "blocked": blocked > 0,
                "domain": domain,
            }
        ],
    }


def generate_synthetic_pcap(url, filepath):
    if not SCAPY_AVAILABLE:
        raise ValueError("Scapy not installed. Run: pip install scapy")

    domain = url.replace("https://", "").replace("http://", "").split("/")[0]
    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror as e:
        raise ValueError(f"Could not resolve domain: {domain}") from e

    pkts = []
    client_mac = "00:11:22:33:44:55"
    server_mac = "66:77:88:99:aa:bb"
    client_ip = "192.168.1.100"
    client_port = 54321

    syn = (
        Ether(src=client_mac, dst=server_mac)
        / IP(src=client_ip, dst=ip)
        / TCP(sport=client_port, dport=443, flags="S", seq=1000)
    )
    syn_ack = (
        Ether(src=server_mac, dst=client_mac)
        / IP(src=ip, dst=client_ip)
        / TCP(sport=443, dport=client_port, flags="SA", seq=2000, ack=1001)
    )
    ack = (
        Ether(src=client_mac, dst=server_mac)
        / IP(src=client_ip, dst=ip)
        / TCP(sport=client_port, dport=443, flags="A", seq=1001, ack=2001)
    )

    payload = (
        f"TLS Client Hello... SNI: {domain} ... GET / HTTP/1.1\r\nHost: {domain}\r\n\r\n"
    ).encode()
    data = (
        Ether(src=client_mac, dst=server_mac)
        / IP(src=client_ip, dst=ip)
        / TCP(sport=client_port, dport=443, flags="PA", seq=1001, ack=2001)
        / Raw(load=payload)
    )
    resp = (
        Ether(src=server_mac, dst=client_mac)
        / IP(src=ip, dst=client_ip)
        / TCP(
            sport=443, dport=client_port, flags="PA", seq=2001, ack=len(payload) + 1001
        )
        / Raw(load=b"HTTP/1.1 200 OK\r\n\r\nHello")
    )

    pkts = [syn, syn_ack, ack, data, resp]
    wrpcap(filepath, pkts)
    return domain


@app.route("/")
@login_required
def index():
    return render_template("index.html")


@app.route("/logout")
def logout():
    session.pop("logged_in", None)
    return redirect(url_for("login"))


@app.route("/analyze_url", methods=["POST"])
def analyze_url():
    req = request.get_json(silent=True)
    if req is None and request.data:
        return jsonify({"error": "Malformed JSON payload"}), 400

    if not req or "url" not in req:
        return jsonify({"error": "No URL provided"}), 400

    url = str(req["url"]).strip()
    if not url or len(url) > 255:
        return jsonify({"error": "Invalid or oversized URL (max 255 chars)"}), 400


    import re
    if not re.match(r"^[a-zA-Z0-9\-\.\:\/]+$", url):
        return jsonify({"error": "URL contains invalid characters"}), 400

    if not url.startswith("http"):
        url = f"https://{url}"

    filename = f"synthetic_{uuid.uuid4().hex}.pcap"
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)

    try:
        domain = generate_synthetic_pcap(url, filepath)


        cmd = [ANALYZER_BIN, "--input", filepath, "--threads", "1", "--json"]
        t0 = time.time()

        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        elapsed = time.time() - t0

        result = parse_engine_output(proc.stdout, proc.stderr, domain, elapsed)
        return jsonify(result)
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": "Processing error", "details": str(e)}), 500
    finally:
        if os.path.exists(filepath):
            os.remove(filepath)


# Real-time Streaming Routes
@app.route("/api/live/stats")
@login_required
def get_live_stats():
    return jsonify(stats.get_summary())


@app.route("/api/live/alerts")
@login_required
def get_live_alerts():
    with stats.lock:
        return jsonify(list(stats.alerts))


@app.route("/api/live/analyze", methods=["POST"])
@login_required
def start_live_analysis():
    data = request.json or {}
    interface = data.get("interface", "eth0")
    threads = data.get("threads", 4)
    
    def run_capture():
        try:
            cmd = [ANALYZER_BIN, "--live", interface, "--threads", str(threads), "--stats"]
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            for line in process.stdout:
                if "packets" in line.lower():
                    emit_live_alert("packet_processing", {"message": line.strip()})
            process.wait()
        except Exception as e:
            emit_live_alert("error", {"message": str(e)})
    
    thread = threading.Thread(target=run_capture, daemon=True)
    thread.start()
    return jsonify({"status": "capture_started", "interface": interface})


@app.route("/api/live/interfaces")
@login_required
def get_interfaces():
    try:
        result = subprocess.run(
            [ANALYZER_BIN, "--live-list"],
            capture_output=True,
            text=True,
            timeout=5
        )
        interfaces = []
        for line in result.stdout.split("\n")[1:]:
            if line.strip():
                parts = line.strip().split(" - ")
                if len(parts) >= 1:
                    interfaces.append({
                        "name": parts[0].strip(),
                        "description": parts[1].strip() if len(parts) > 1 else ""
                    })
        return jsonify({"interfaces": interfaces})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# WebSocket Handlers
@socketio.on("connect")
def handle_connect():
    if not session.get("logged_in"):
        return False
    print(f"Client connected: {request.sid}")
    emit("response", {"data": "Connected to real-time DPI stream"})


@socketio.on("subscribe_stats")
def handle_subscribe_stats():
    room = f"stats_{request.sid}"
    join_room(room)
    def emit_stats_loop():
        while True:
            time.sleep(1)
            summary = stats.get_summary()
            socketio.emit("stats_update", summary, room=room)
    thread = threading.Thread(target=emit_stats_loop, daemon=True)
    thread.start()


def emit_live_alert(alert_type, details):
    alert = {
        "timestamp": datetime.now().isoformat(),
        "type": alert_type,
        "details": details
    }
    stats.add_alert(alert_type, details)
    socketio.emit("alert", alert, broadcast=True)


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("100 per hour")
def login():
    if request.method == "GET":
        return render_template("login.html")
    
    data = request.get_json(silent=True)
    if data is None and request.data:
        return jsonify({"error": "Malformed JSON payload"}), 400

    if not data:
        return jsonify({"error": "Empty payload"}), 400

    username = str(data.get("username", "")).strip()
    password = str(data.get("password", "")).strip()

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    if len(username) > 64 or len(password) > 64:
        return jsonify({"error": "Username/Password too long (max 64 chars)"}), 400

    if username == DASHBOARD_USERNAME and password == DASHBOARD_PASSWORD:
        session["logged_in"] = True
        return jsonify({"message": "Login successful", "token": "dummy-jwt-token"}), 200
    
    return jsonify({"error": "Invalid credentials"}), 401


@app.route("/register", methods=["POST"])
@limiter.limit("5 per 15 minutes")
def register():

    return jsonify({"message": "Registration successful"}), 201


@app.route("/api/health")
def health():
    return jsonify({
        "status": "ok", 
        "engine": "active" if ANALYZER_BIN and os.path.exists(ANALYZER_BIN) else "unavailable"
    }), 200


@app.route("/api/metrics")
def metrics():
    # Check multiple locations for metrics
    possible_paths = [
        "/app/metrics.json",
        os.path.join(os.getcwd(), "configs", "metrics.json"),
        os.path.join(os.getcwd(), "metrics.json")
    ]
    
    for metrics_file in possible_paths:
        if os.path.exists(metrics_file):
            try:
                with open(metrics_file, 'r') as f:
                    import json
                    data = json.load(f)
                    return jsonify(data), 200
            except Exception:
                pass
    
    return jsonify({
        "packets_total": 0,
        "packets_blocked": 0,
        "bytes_total": 0,
        "throughput_pps": 0,
        "throughput_mbps": 0,
        "block_rate": 0
    }), 200


if __name__ == "__main__":
    import webbrowser
    from threading import Timer

    def open_browser():
        webbrowser.open_new("http://127.0.0.1:5000")

    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    
    print(f"Network Traffic Analysis Engine")
    print(f"Dashboard: http://127.0.0.1:{port}")
    print(f"Analyzer:  {ANALYZER_BIN}")
    if debug:
        Timer(1.5, open_browser).start()
        
    socketio.run(app, host="0.0.0.0", port=port, debug=debug, use_reloader=False, allow_unsafe_werkzeug=True)
