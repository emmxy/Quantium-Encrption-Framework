"""
Integration and security tests for Flask Web Application, WAF/IPS middleware, and Admin Routes.
Uses local in-process Flask test client without external network requirements.
"""

import os
import io
import json
import pytest
from app import app, ADMIN_API_KEY, threat_detector


@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


@pytest.fixture(autouse=True)
def reset_threat_state():
    threat_detector.user_sessions.clear()
    threat_detector.manual_blocklist.clear()
    threat_detector.activity_log.clear()
    threat_detector.security_events.clear()
    yield
    threat_detector.user_sessions.clear()
    threat_detector.manual_blocklist.clear()


class TestWebAppSecurity:

    def test_dashboard_route_status(self, client):
        response = client.get('/')
        assert response.status_code == 200

    def test_generate_keys_route(self, client):
        response = client.post('/generate_keys', data={'algorithm': 'kyber768'})
        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert os.path.exists(data['public_key_path'])
        assert os.path.exists(data['private_key_path'])

    def test_encrypt_and_decrypt_text_flow(self, client):
        # 1. Generate keys
        res_keys = client.post('/generate_keys', data={'algorithm': 'kyber768'})
        keys = res_keys.get_json()

        # 2. Encrypt text
        sample_msg = "Confidential web app integration test payload"
        res_enc = client.post('/encrypt_text', json={
            'text': sample_msg,
            'public_key_path': keys['public_key_path']
        })
        assert res_enc.status_code == 200
        enc_payload = res_enc.get_json()
        assert enc_payload['success'] is True
        encrypted_data = enc_payload['encrypted_data']

        # 3. Decrypt text
        res_dec = client.post('/decrypt_text', json={
            'encrypted_data': encrypted_data,
            'private_key_path': keys['private_key_path']
        })
        assert res_dec.status_code == 200
        dec_payload = res_dec.get_json()
        assert dec_payload['success'] is True
        assert dec_payload['plaintext'] == sample_msg

    def test_decrypt_tampered_ciphertext_returns_error(self, client):
        # Generate keys
        res_keys = client.post('/generate_keys', data={'algorithm': 'kyber768'})
        keys = res_keys.get_json()

        # Encrypt text
        res_enc = client.post('/encrypt_text', json={
            'text': "Original sensitive message",
            'public_key_path': keys['public_key_path']
        })
        encrypted_data = res_enc.get_json()['encrypted_data']

        # Tamper with the ciphertext
        tampered_data = dict(encrypted_data)
        tampered_data['aes_ciphertext'] = "AAAA" + tampered_data['aes_ciphertext'][4:]

        res_dec = client.post('/decrypt_text', json={
            'encrypted_data': tampered_data,
            'private_key_path': keys['private_key_path']
        })
        assert res_dec.status_code == 400
        dec_payload = res_dec.get_json()
        assert dec_payload['success'] is False
        assert "tampered" in dec_payload['error'].lower() or "authentication" in dec_payload['error'].lower()

    def test_encrypt_and_decrypt_file_flow(self, client):
        # Generate keys
        res_keys = client.post('/generate_keys', data={'algorithm': 'kyber768'})
        keys = res_keys.get_json()

        # Encrypt file
        file_bytes = b"Sample binary file stream for Flask upload"
        res_enc = client.post('/encrypt_file', data={
            'file': (io.BytesIO(file_bytes), 'upload_sample.txt'),
            'public_key_path': keys['public_key_path']
        }, content_type='multipart/form-data')
        assert res_enc.status_code == 200
        enc_meta = res_enc.get_json()

        # Decrypt file
        with open(enc_meta['encrypted_file_path'], 'rb') as f:
            enc_file_data = f.read()
        with open(enc_meta['metadata_path'], 'rb') as f:
            meta_json_data = f.read()

        res_dec = client.post('/decrypt_file', data={
            'encrypted_file': (io.BytesIO(enc_file_data), 'enc.bin'),
            'metadata_file': (io.BytesIO(meta_json_data), 'meta.json'),
            'private_key_path': keys['private_key_path']
        }, content_type='multipart/form-data')
        assert res_dec.status_code == 200
        dec_res = res_dec.get_json()
        assert dec_res['success'] is True

        with open(dec_res['decrypted_file_path'], 'rb') as f:
            assert f.read() == file_bytes

    def test_waf_blocks_sqli_payload(self, client):
        response = client.get('/?query=1 UNION SELECT * FROM users--')
        assert response.status_code == 403
        assert "Malicious request blocked by AI IPS" in response.get_data(as_text=True)

    def test_waf_blocks_xss_payload(self, client):
        response = client.post('/chat', data='{"message": "<script>alert(1)</script>"}', content_type='application/json')
        assert response.status_code == 403
        assert "Malicious request blocked by AI IPS" in response.get_data(as_text=True)

    def test_waf_blocks_path_traversal_payload(self, client):
        response = client.get('/download?file=../../../../etc/passwd')
        assert response.status_code == 403

    def test_download_prevents_arbitrary_file_read(self, client):
        # Attempt to read application source code
        res_code = client.get('/download?file=app.py')
        assert res_code.status_code == 403

        # Attempt to read private keys
        res_key = client.get('/download?file=keys/public_key_sample.key')
        assert res_key.status_code == 403

    def test_admin_route_unauthorized_without_key(self, client):
        response = client.post('/api/block_ip', json={'ip_address': '192.168.1.100'})
        assert response.status_code == 401

    def test_admin_route_authorized_with_key(self, client):
        test_blocked_ip = '10.20.30.40'
        response = client.post(
            '/api/block_ip',
            headers={'X-Admin-Key': ADMIN_API_KEY},
            json={'ip_address': test_blocked_ip}
        )
        assert response.status_code == 200
        assert response.get_json()['success'] is True
        assert test_blocked_ip in threat_detector.manual_blocklist

        # Subsequent requests from blocked IP must be forbidden (403)
        res_blocked = client.get('/', environ_base={'REMOTE_ADDR': test_blocked_ip})
        assert res_blocked.status_code == 403
