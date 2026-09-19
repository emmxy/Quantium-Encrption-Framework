import json, io
try:
    print(json.load(io.BytesIO(b'{"a": 1}')))
except Exception as e:
    print("Error:", repr(e))
