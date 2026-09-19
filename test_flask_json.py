from flask import Flask, request
import io
from werkzeug.datastructures import FileStorage
import json

app = Flask(__name__)

@app.route('/', methods=['POST'])
def test():
    file = request.files['file']
    try:
        data = json.load(file)
        return str(data)
    except Exception as e:
        return repr(e), 500

if __name__ == '__main__':
    with app.test_client() as c:
        res = c.post('/', data={'file': (io.BytesIO(b'{"a": 1}'), 'test.json')})
        print(res.data.decode())
