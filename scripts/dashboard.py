import os
import subprocess
import json
import socket
import uuid
from flask import Flask, request, render_template, jsonify

try:
    from scapy.all import IP, TCP, Ether, wrpcap, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB limit

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Path to the analyzer binary
ANALYZER_BIN = os.environ.get('ANALYZER_BIN')
if not ANALYZER_BIN:
    if os.name == 'nt':
        ANALYZER_BIN = os.path.join('build', 'high_performance_engine.exe')
    else:
        # Check common Linux locations
        possible_paths = [
            './high_performance_engine',
            'build/high_performance_engine',
            '/app/high_performance_engine'
        ]
        for p in possible_paths:
            if os.path.exists(p):
                ANALYZER_BIN = p
                break
        if not ANALYZER_BIN:
            ANALYZER_BIN = 'high_performance_engine' # assume in PATH

@app.route('/')
def index():
    return render_template('index.html')

def generate_synthetic_pcap(url, filepath):
    if not SCAPY_AVAILABLE:
        raise ValueError("Scapy is not installed. Run 'pip install scapy' to use this feature.")
    
    domain = url.replace("https://", "").replace("http://", "").split("/")[0]
    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror:
        raise ValueError(f"Could not resolve domain: {domain}")

    # Generate synthetic packets bypassing Windows routing table by providing explicit src/dst
    pkts = []
    client_mac = "00:11:22:33:44:55"
    server_mac = "66:77:88:99:aa:bb"
    client_ip = "192.168.1.100"
    client_port = 54321
    
    # Client -> Server (SYN)
    syn = Ether(src=client_mac, dst=server_mac)/IP(src=client_ip, dst=ip)/TCP(sport=client_port, dport=443, flags='S', seq=1000)
    pkts.append(syn)
    
    # Server -> Client (SYN-ACK)
    syn_ack = Ether(src=server_mac, dst=client_mac)/IP(src=ip, dst=client_ip)/TCP(sport=443, dport=client_port, flags='SA', seq=2000, ack=1001)
    pkts.append(syn_ack)
    
    # Client -> Server (ACK)
    ack = Ether(src=client_mac, dst=server_mac)/IP(src=client_ip, dst=ip)/TCP(sport=client_port, dport=443, flags='A', seq=1001, ack=2001)
    pkts.append(ack)
    
    # To trigger Aho-Corasick app matching, we put the domain in the payload
    payload = f"TLS Client Hello... SNI: {domain} ... GET / HTTP/1.1\r\nHost: {domain}\r\n\r\n".encode('utf-8')
    data = Ether(src=client_mac, dst=server_mac)/IP(src=client_ip, dst=ip)/TCP(sport=client_port, dport=443, flags='PA', seq=1001, ack=2001) / Raw(load=payload)
    pkts.append(data)
    
    # Server -> Client (Data)
    resp = Ether(src=server_mac, dst=client_mac)/IP(src=ip, dst=client_ip)/TCP(sport=443, dport=client_port, flags='PA', seq=2001, ack=len(payload)+1001) / Raw(load=b"HTTP/1.1 200 OK\r\n\r\nHello")
    pkts.append(resp)
    
    wrpcap(filepath, pkts)

@app.route('/analyze_url', methods=['POST'])
def analyze_url():
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({'error': 'No URL provided'}), 400
    
    url = data['url'].strip()
    if not url:
        return jsonify({'error': 'Empty URL'}), 400

    filename = f"synthetic_{uuid.uuid4().hex}.pcap"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    try:
        generate_synthetic_pcap(url, filepath)
        
        # Run the analyzer with JSON output
        cmd = [ANALYZER_BIN, '--input', filepath, '--json', '--threads', '4']
        engine_proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
        engine_stdout = str(engine_proc.stdout)
        
        # Extract JSON blob from engine output
        analyzer_output = str(engine_stdout)
        json_start = analyzer_output.find('{')
        json_end = analyzer_output.rfind('}')
        
        if json_start == -1 or json_end == -1:
            return jsonify({'error': 'Failed to locate JSON data in analyzer output'}), 500
            
        json_blob = analyzer_output[json_start : json_end + 1]
        analysis_data = json.loads(json_blob)
        analysis_data['simulated_domain'] = url
        return jsonify(analysis_data)
        
    except Exception as e:
        import traceback
        err_info = {
            'error': str(e),
            'type': type(e).__name__,
            'traceback': traceback.format_exc()
        }
        # Try to include raw stdout if it exists in local scope
        try:
            err_info['raw_stdout'] = engine_proc.stdout
        except UnboundLocalError:
            pass
        return jsonify({'error': f"Internal Error: {str(e)} | Details: {err_info}"}), 500
    finally:
        if os.path.exists(filepath):
            os.remove(filepath)


if __name__ == '__main__':
    print("Dashboard starting on http://127.0.0.1:5000")
    app.run(debug=True, port=5000)
