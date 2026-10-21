import requests
import time

URL = "http://127.0.0.1:5000"

def run_defense_checks():
    print("--- Testing WAF (SQLi) ---")
    try:
        res = requests.get(f"{URL}/?query=UNION SELECT * FROM users")
        print("Response:", res.status_code)
        print(res.text)
    except Exception as e:
        print("Could not connect to live server:", e)
        return

    print("\n--- Testing Rate Limiting ---")
    for i in range(55):
        res = requests.get(f"{URL}/")
        if res.status_code == 429:
            print(f"Request {i+1} got blocked by Rate Limiter! (429 Too Many Requests)")
            break
        
    print("\n--- Testing AI Threat Limiting ---")
    for i in range(12):
        res = requests.post(f"{URL}/decrypt_text", json={'encrypted_data': 'fake', 'private_key_path': 'fake'})
        if res.status_code == 403:
            print(f"Request {i+1} got blocked by AI IPS! (403 Forbidden)")
            print(res.text)
            break

if __name__ == '__main__':
    run_defense_checks()
