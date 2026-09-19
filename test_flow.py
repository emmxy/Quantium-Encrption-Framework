import urllib.request
import urllib.parse
import json
import io

base_url = 'http://localhost:5000'

def post_multipart(url, fields, files):
    import mimetypes
    boundary = '----------Boundary1234567890'
    body = []
    for key, value in fields.items():
        body.append('--' + boundary)
        body.append('Content-Disposition: form-data; name="%s"' % key)
        body.append('')
        body.append(value)
    for key, (filename, filedata) in files.items():
        body.append('--' + boundary)
        body.append('Content-Disposition: form-data; name="%s"; filename="%s"' % (key, filename))
        body.append('Content-Type: %s' % (mimetypes.guess_type(filename)[0] or 'application/octet-stream'))
        body.append('')
        body.append(filedata.decode('latin1')) # hack for binary
    body.append('--' + boundary + '--')
    body.append('')
    body_data = '\r\n'.join(body).encode('latin1')
    req = urllib.request.Request(url, data=body_data)
    req.add_header('Content-Type', 'multipart/form-data; boundary=%s' % boundary)
    return urllib.request.urlopen(req)

# Generate keys
data = urllib.parse.urlencode({'algorithm': 'kyber768'}).encode()
req = urllib.request.Request(f"{base_url}/generate_keys", data=data)
res = urllib.request.urlopen(req)
keys = json.loads(res.read())
print("Keys generated", keys)

# Encrypt file
with open('test.txt', 'wb') as f:
    f.write(b'Hello world')

with open('test.txt', 'rb') as f:
    files = {'file': ('test.txt', f.read())}
fields = {'public_key_path': keys['public_key_path']}
res = post_multipart(f"{base_url}/encrypt_file", fields, files)
enc_data = json.loads(res.read())
print("Encryption result", enc_data)

# Decrypt file
with open(enc_data['encrypted_file_path'], 'rb') as f:
    enc_file_bytes = f.read()
with open(enc_data['metadata_path'], 'rb') as f:
    meta_bytes = f.read()

files = {
    'encrypted_file': ('enc.bin', enc_file_bytes),
    'metadata_file': ('meta.json', meta_bytes)
}
fields = {'private_key_path': keys['private_key_path']}
try:
    res = post_multipart(f"{base_url}/decrypt_file", fields, files)
    print("Decryption result", res.read())
except urllib.error.HTTPError as e:
    print("HTTP Error:", e.code, e.read().decode())
