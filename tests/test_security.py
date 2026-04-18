import requests
import json

BASE_URL = "http://127.0.0.1:5000"

def test_xss_protection():
    print("Testing XSS protection in dashboard...")




    resp = requests.get(BASE_URL)
    if "function esc(str)" in resp.text:
        print("SUCCESS: esc() helper found in index.html")
    else:
        print("FAILED: esc() helper not found")

def test_traceback_exposure():
    print("\nTesting for sensitive traceback exposure...")


    resp = requests.post(f"{BASE_URL}/analyze_url", json={"url": "!!!invalid!!!"})
    data = resp.json()
    print(f"Status: {resp.status_code}, Body: {json.dumps(data, indent=2)}")
    
    if "traceback" in data:
        print("FAILED: Traceback still exposed!")
    else:
        print("SUCCESS: No traceback in error response")

if __name__ == "__main__":

    test_xss_protection()
    test_traceback_exposure()
    print("\nSecurity verification complete.")