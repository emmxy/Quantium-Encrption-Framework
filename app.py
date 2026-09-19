"""
Flask Web Dashboard for Quantum-Resistant PKI Encryption Tool
Provides web-based interface for encryption operations
"""

from flask import Flask, render_template, request, jsonify, send_file, flash, redirect, url_for, abort
from werkzeug.utils import secure_filename
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os
import json
from datetime import datetime
from flask_socketio import SocketIO, emit, join_room, leave_room
from kyber_encryption import KyberEncryption
from hybrid_encryption import HybridEncryption
from threat_detection import ThreatDetection
from performance import PerformanceEvaluator

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")
app.secret_key = os.urandom(32)
active_chat_sessions = {}  # Store sid -> private_key mapping for chat
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['KEYS_FOLDER'] = 'keys'
app.config['ENCRYPTED_FOLDER'] = 'encrypted'
app.config['DECRYPTED_FOLDER'] = 'decrypted'

# Create necessary directories
for folder in [app.config['UPLOAD_FOLDER'], app.config['KEYS_FOLDER'], 
               app.config['ENCRYPTED_FOLDER'], app.config['DECRYPTED_FOLDER']]:
    os.makedirs(folder, exist_ok=True)

# Initialize components
threat_detector = ThreatDetection()
performance_evaluator = PerformanceEvaluator()

# Initialize Rate Limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Basic WAF (Web Application Firewall) payload signatures
MALICIOUS_PAYLOADS = [
    "<script>", "javascript:", "onload=", "onerror=",  # XSS
    "UNION SELECT", "DROP TABLE", "--", "1=1", "OR 1=1",  # SQLi
    "../", "..\\", "/etc/passwd", "cmd.exe"  # Path traversal / LFI / RCE
]

@app.before_request
def security_middleware():
    """
    Middleware that runs before every request to provide IPS and WAF capabilities.
    """
    client_ip = request.remote_addr or 'anonymous'
    
    # 1. IPS Component: Check Manual Blocklist and AI Threat Detector Risk Score
    if client_ip in threat_detector.manual_blocklist:
        abort(403, description="Your IP has been manually blocked by the administrator.")
        
    session_status = threat_detector.get_session_status(client_ip)
    if session_status and session_status.get('risk_score', 0) > 50:
        # Block the request if the AI indicates high risk
        abort(403, description="Your IP has been temporarily blocked due to anomalous activity detected by the AI.")
        
    # 2. WAF Component: Inspect URL and Data for Malicious Payloads
    request_data = str(request.args) + str(request.form) + str(request.data)
    for payload in MALICIOUS_PAYLOADS:
        if payload.lower() in request_data.lower():
            # Log WAF trigger to the AI Threat Detector
            threat_detector.log_activity('web_request', success=False, event_type='waf_payload_detected', user_id=client_ip)
            abort(403, description="Malicious payload detected and blocked by WAF.")


@app.route('/')
def index():
    """Main dashboard page."""
    stats = threat_detector.get_statistics()
    return render_template('index.html', stats=stats)


@app.route('/generate_keys', methods=['GET', 'POST'])
def generate_keys():
    """Generate new Kyber key pair."""
    if request.method == 'POST':
        try:
            algorithm = request.form.get('algorithm', 'kyber768')
            kyber = KyberEncryption(algorithm)
            public_key, private_key = kyber.generate_keypair()
            
            # Save keys
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            public_key_path = os.path.join(app.config['KEYS_FOLDER'], 
                                         f'public_key_{timestamp}.key')
            private_key_path = os.path.join(app.config['KEYS_FOLDER'], 
                                          f'private_key_{timestamp}.key')
            
            kyber.save_keypair(public_key, private_key, 
                             public_key_path, private_key_path)
            
            # Log activity
            client_ip = request.remote_addr or 'anonymous'
            threat_detector.log_activity('encrypt', algorithm=algorithm, 
                                        file_size=0, success=True, user_id=client_ip)
            
            flash(f'Keys generated successfully using {algorithm}!', 'success')
            return jsonify({
                'success': True,
                'public_key_path': public_key_path,
                'private_key_path': private_key_path,
                'algorithm': algorithm
            })
        except Exception as e:
            flash(f'Error generating keys: {str(e)}', 'error')
            return jsonify({'success': False, 'error': str(e)}), 400
    
    return render_template('generate_keys.html')


@app.route('/encrypt_text', methods=['GET', 'POST'])
def encrypt_text():
    """Encrypt text."""
    if request.method == 'POST':
        try:
            data = request.get_json()
            plaintext = data.get('text')
            public_key_path = data.get('public_key_path')
            
            if not plaintext or not public_key_path:
                return jsonify({'success': False, 'error': 'Missing data'}), 400
            
            # Load public key
            with open(public_key_path, 'rb') as f:
                public_key = f.read()
            
            # Encrypt
            hybrid = HybridEncryption()
            encrypted_data = hybrid.encrypt_text(plaintext, public_key)
            
            # Save encrypted data
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_path = os.path.join(app.config['ENCRYPTED_FOLDER'], 
                                     f'encrypted_text_{timestamp}.json')
            hybrid.save_encrypted_data(encrypted_data, output_path)
            
            # Log activity
            client_ip = request.remote_addr or 'anonymous'
            threat_detector.log_activity('encrypt', file_size=len(plaintext.encode()),
                                        success=True, algorithm=encrypted_data['algorithm'], user_id=client_ip)
            
            return jsonify({
                'success': True,
                'encrypted_data': encrypted_data,
                'output_path': output_path
            })
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 400
    
    return render_template('encrypt_text.html')


@app.route('/decrypt_text', methods=['GET', 'POST'])
def decrypt_text():
    """Decrypt text."""
    if request.method == 'POST':
        try:
            data = request.get_json()
            encrypted_data = data.get('encrypted_data')
            private_key_path = data.get('private_key_path')
            
            if not encrypted_data or not private_key_path:
                return jsonify({'success': False, 'error': 'Missing data'}), 400
            
            # Load private key
            with open(private_key_path, 'rb') as f:
                private_key = f.read()
            
            # Decrypt
            hybrid = HybridEncryption()
            plaintext = hybrid.decrypt_text(encrypted_data, private_key)
            
            # Log activity
            client_ip = request.remote_addr or 'anonymous'
            threat_detector.log_activity('decrypt', file_size=len(plaintext.encode()),
                                        success=True, user_id=client_ip)
            
            return jsonify({
                'success': True,
                'plaintext': plaintext
            })
        except Exception as e:
            # Log failed decryption with specific event type
            error_msg = str(e).lower()
            event_type = 'kyber_decapsulation_failed' if 'kyber' in error_msg or 'key' in error_msg else 'aes_decrypt_failed'
            client_ip = request.remote_addr or 'anonymous'
            threat_detector.log_activity('decrypt', success=False, event_type=event_type, 
                                        algorithm='kyber768', user_id=client_ip)
            return jsonify({'success': False, 'error': str(e)}), 400
    
    return render_template('decrypt_text.html')


@app.route('/encrypt_file', methods=['GET', 'POST'])
def encrypt_file():
    """Encrypt file upload."""
    if request.method == 'POST':
        try:
            if 'file' not in request.files:
                return jsonify({'success': False, 'error': 'No file provided'}), 400
            
            file = request.files['file']
            public_key_path = request.form.get('public_key_path')
            
            if file.filename == '' or not public_key_path:
                return jsonify({'success': False, 'error': 'Missing data'}), 400
            
            # Save uploaded file
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            
            # Load public key
            with open(public_key_path, 'rb') as f:
                public_key = f.read()
            
            # Encrypt file
            hybrid = HybridEncryption()
            encrypted_data, encrypted_bytes = hybrid.encrypt_file(file_path, public_key)
            
            # Save encrypted file
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            encrypted_file_path = os.path.join(app.config['ENCRYPTED_FOLDER'],
                                              f'encrypted_{timestamp}.bin')
            metadata_path = os.path.join(app.config['ENCRYPTED_FOLDER'],
                                       f'encrypted_{timestamp}.json')
            
            with open(encrypted_file_path, 'wb') as f:
                f.write(encrypted_bytes)
            
            hybrid.save_encrypted_data(encrypted_data, metadata_path)
            
            # Log activity
            client_ip = request.remote_addr or 'anonymous'
            file_size = os.path.getsize(file_path)
            threat_detector.log_activity('encrypt', file_size=file_size,
                                        success=True, algorithm=encrypted_data['algorithm'], user_id=client_ip)
            
            return jsonify({
                'success': True,
                'encrypted_file_path': encrypted_file_path,
                'metadata_path': metadata_path,
                'original_filename': encrypted_data['original_filename']
            })
        except Exception as e:
            client_ip = request.remote_addr or 'anonymous'
            threat_detector.log_activity('encrypt', success=False, user_id=client_ip)
            return jsonify({'success': False, 'error': str(e)}), 400
    
    return render_template('encrypt_file.html')


@app.route('/decrypt_file', methods=['GET', 'POST'])
def decrypt_file():
    """Decrypt file."""
    if request.method == 'POST':
        try:
            if 'encrypted_file' not in request.files:
                return jsonify({'success': False, 'error': 'No file provided'}), 400
            
            encrypted_file = request.files['encrypted_file']
            metadata_file = request.files['metadata_file']
            private_key_path = request.form.get('private_key_path')
            
            if not metadata_file or not private_key_path:
                return jsonify({'success': False, 'error': 'Missing data'}), 400
            
            # Load encrypted data
            encrypted_data = json.load(metadata_file)
            encrypted_bytes = encrypted_file.read()
            
            # Load private key
            with open(private_key_path, 'rb') as f:
                private_key = f.read()
            
            # Decrypt
            hybrid = HybridEncryption()
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            original_filename = encrypted_data.get('original_filename', 'decrypted_file')
            output_path = os.path.join(app.config['DECRYPTED_FOLDER'],
                                     f'decrypted_{timestamp}_{original_filename}')
            
            decrypted_bytes = hybrid.decrypt_file(encrypted_data, encrypted_bytes,
                                                 private_key, output_path)
            
            # Log activity
            client_ip = request.remote_addr or 'anonymous'
            threat_detector.log_activity('decrypt', file_size=len(decrypted_bytes),
                                        success=True, user_id=client_ip)
            
            return jsonify({
                'success': True,
                'decrypted_file_path': output_path,
                'filename': original_filename
            })
        except Exception as e:
            # Log failed file decryption with specific event type
            error_msg = str(e).lower()
            event_type = 'kyber_decapsulation_failed' if 'kyber' in error_msg or 'key' in error_msg else 'aes_decrypt_failed'
            client_ip = request.remote_addr or 'anonymous'
            threat_detector.log_activity('decrypt', success=False, event_type=event_type, user_id=client_ip)
            return jsonify({'success': False, 'error': str(e)}), 400
    
    return render_template('decrypt_file.html')


@app.route('/download')
def download_file():
    """Download a file."""
    filepath = request.args.get('file')
    if not filepath or not os.path.exists(filepath):
        abort(404, description="File not found")
    
    # Basic path traversal prevention
    if '..' in filepath or filepath.startswith('/') or filepath.startswith('\\'):
        abort(403, description="Invalid path")
        
    return send_file(filepath, as_attachment=True)


@app.route('/threat_analysis')
def threat_analysis():
    """Display threat analysis report."""
    threats = threat_detector.detect_threats()
    stats = threat_detector.get_statistics()
    return render_template('threat_analysis.html', threats=threats, stats=stats)


@app.route('/performance')
def performance():
    """Display performance evaluation."""
    if request.args.get('run'):
        results = performance_evaluator.run_full_evaluation()
        return jsonify(results)
    return render_template('performance.html')


@app.route('/api/threats')
def api_threats():
    """API endpoint for threat data."""
    threats = threat_detector.detect_threats()
    return jsonify(threats)


@app.route('/api/stats')
def api_stats():
    """API endpoint for statistics."""
    stats = threat_detector.get_statistics()
    return jsonify(stats)


@app.route('/api/sessions')
def api_sessions():
    """API endpoint for real-time session status."""
    session_status = threat_detector.get_session_status()
    return jsonify(session_status)


@app.route('/api/security-events')
def api_security_events():
    """API endpoint for security events log."""
    # Get recent security events (last 100)
    events = threat_detector.security_events[-100:] if hasattr(threat_detector, 'security_events') else []
    return jsonify(events)


@app.route('/api/block_ip', methods=['POST'])
def api_block_ip():
    """API endpoint to manually block an IP address."""
    data = request.get_json()
    ip_address = data.get('ip_address')
    if not ip_address:
        return jsonify({'success': False, 'error': 'No IP address provided'}), 400
        
    try:
        threat_detector.block_ip(ip_address)
        return jsonify({'success': True, 'message': f'IP {ip_address} successfully blocked.'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# --- Real-Time E2EE Chat Routes & SocketIO Events ---

@app.route('/chat')
def chat():
    """Real-time Chat interface backed by Server-side Kyber/Hybrid Encryption."""
    return render_template('chat.html')

@socketio.on('connect')
def handle_connect():
    """Handle new WebSocket connection."""
    pass

@socketio.on('disconnect')
def handle_disconnect():
    if request.sid in active_chat_sessions:
        del active_chat_sessions[request.sid]

@socketio.on('join_chat')
def on_join_chat(data):
    """
    Client joins a chat room. Server generates Kyber keys for them.
    """
    room = data.get('room', 'general')
    username = data.get('username', 'Anonymous')
    join_room(room)
    
    try:
        # Generate real Kyber keypair
        kyber = KyberEncryption('kyber768')
        public_key, private_key = kyber.generate_keypair()
        
        # Store private key in server session
        active_chat_sessions[request.sid] = private_key
        
        import base64
        pk_b64 = base64.b64encode(public_key).decode('utf-8')
        
        # Send keys back to the user
        emit('chat_keys_generated', {'public_key': pk_b64, 'username': username})
        
        # Announce to room
        emit('user_joined_chat', {
            'sid': request.sid,
            'username': username,
            'public_key': pk_b64
        }, room=room, include_self=False)
    except Exception as e:
        emit('chat_error', {'error': str(e)})

@socketio.on('send_chat_message')
def on_send_chat_message(data):
    """
    Client wants to send a message. Server encrypts it with recipient's public key.
    """
    room = data.get('room')
    text = data.get('text')
    recipient_pk_b64 = data.get('recipient_public_key')
    sender_name = data.get('username', 'Anonymous')
    
    if not all([room, text, recipient_pk_b64]):
        return
        
    try:
        import base64
        recipient_pk = base64.b64decode(recipient_pk_b64)
        
        # Use real HybridEncryption
        hybrid = HybridEncryption()
        encrypted_data = hybrid.encrypt_text(text, recipient_pk)
        
        # Log to threat detector
        client_ip = request.remote_addr or 'anonymous'
        threat_detector.log_activity('encrypt', file_size=len(text.encode()),
                                    success=True, algorithm=encrypted_data['algorithm'], user_id=client_ip)
        
        # Broadcast encrypted message to room
        emit('receive_chat_message', {
            'sender_sid': request.sid,
            'sender_name': sender_name,
            'encrypted_data': encrypted_data
        }, room=room, include_self=False)
        
    except Exception as e:
        emit('chat_error', {'error': str(e)})

@socketio.on('request_decryption')
def on_request_decryption(data):
    """
    Client received an encrypted message and asks server to decrypt it using their stored private key.
    """
    encrypted_data = data.get('encrypted_data')
    msg_id = data.get('msg_id')
    
    if not encrypted_data or request.sid not in active_chat_sessions:
        return
        
    try:
        private_key = active_chat_sessions[request.sid]
        hybrid = HybridEncryption()
        plaintext = hybrid.decrypt_text(encrypted_data, private_key)
        
        emit('decryption_result', {
            'msg_id': msg_id,
            'plaintext': plaintext,
            'success': True
        })
    except Exception as e:
        emit('decryption_result', {
            'msg_id': msg_id,
            'error': str(e),
            'success': False
        })

@socketio.on('share_my_key')
def on_share_my_key(data):
    """
    Existing peer in the room shares their key with the newly joined peer.
    """
    room = data.get('room')
    emit('receive_shared_key', {
        'public_key': data.get('public_key'),
        'username': data.get('username')
    }, room=room, include_self=False)

if __name__ == '__main__':
    # Train threat detection model on startup
    threat_detector.train_model()
    socketio.run(app, debug=True, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)

