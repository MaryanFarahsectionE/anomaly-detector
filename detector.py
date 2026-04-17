from scapy.all import sniff, IP, TCP, UDP
from sklearn.ensemble import IsolationForest
from flask import Flask, render_template_string
from collections import defaultdict
import numpy as np
import threading
import time

app = Flask(__name__)
alerts = []

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Anomaly Detector</title>
    <meta http-equiv="refresh" content="2">
    <style>
        body { background: #0a0a0a; color: #00ff00; font-family: monospace; padding: 20px; }
        h1 { color: #ff4444; }
        .alert { background: #1a1a1a; padding: 10px; margin: 5px 0; border-left: 3px solid #ff4444; }
        .normal { color: #888; font-size: 12px; }
    </style>
</head>
<body>
    <h1>Network Anomaly Detector</h1>
    <p class="normal">Auto-refreshes every 2 seconds</p>
    <hr>
    {% if alerts %}
        {% for a in alerts[-20:]|reverse %}
            <div class="alert">{{ a }}</div>
        {% endfor %}
    {% else %}
        <p>No anomalies detected yet...</p>
    {% endif %}
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(TEMPLATE, alerts=alerts)

def run_flask():
    app.run(host="0.0.0.0", port=5000, debug=False)

threading.Thread(target=run_flask, daemon=True).start()

packet_times = defaultdict(list)
feature_buffer = []
model = None
TRAIN_SIZE = 100

def extract_features(packet):
    if not packet.haslayer(IP):
        return None

    proto = packet[IP].proto
    size = len(packet)
    src_ip = packet[IP].src
    dst_port = 0
    syn_flag = 0

    if packet.haslayer(TCP):
        dst_port = packet[TCP].dport
        syn_flag = 1 if packet[TCP].flags == 0x02 else 0
    elif packet.haslayer(UDP):
        dst_port = packet[UDP].dport

    now = time.time()
    packet_times[src_ip].append(now)
    packet_times[src_ip] = [t for t in packet_times[src_ip] if now - t < 1]
    pkt_rate = len(packet_times[src_ip])

    return [proto, size, dst_port, syn_flag, pkt_rate]

def process_packet(packet):
    global model, feature_buffer

    features = extract_features(packet)
    if features is None:
        return

    feature_buffer.append(features)

    if len(feature_buffer) == TRAIN_SIZE and model is None:
        print("[*] Training model on initial traffic...")
        model = IsolationForest(contamination=0.05, random_state=42)
        model.fit(feature_buffer)
        print("[*] Model trained. Now detecting anomalies...")

    if model is not None:
        score = model.predict([features])
        if score[0] == -1:
            src = packet[IP].src
            msg = f"[{time.strftime('%H:%M:%S')}] ALERT from {src} | proto={features[0]} size={features[1]} port={features[2]} syn={features[3]} rate={features[4]}"
            alerts.append(msg)
            print(msg)

print("[*] Starting capture... (Ctrl+C to stop)")
print("[*] Dashboard at http://localhost:5000")
sniff(filter="ip", prn=process_packet, store=False)