"""Print only issuer, audience, and subject of a GitHub OIDC token.

This is a diagnostic, not token validation. Never print the JWT itself.
"""
import base64
import json
import os
import urllib.parse
import urllib.request


def main():
    request_url = os.environ['ACTIONS_ID_TOKEN_REQUEST_URL']
    bearer = os.environ['ACTIONS_ID_TOKEN_REQUEST_TOKEN']
    url = request_url + ('&' if '?' in request_url else '?') + urllib.parse.urlencode({'audience': 'sts.amazonaws.com'})
    request = urllib.request.Request(url, headers={'Authorization': 'Bearer ' + bearer})
    with urllib.request.urlopen(request, timeout=10) as response:
        token = json.load(response)['value']
    payload = token.split('.')[1]
    claims = json.loads(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4)))
    print(json.dumps({field: claims.get(field) for field in ('iss', 'aud', 'sub')}, sort_keys=True))


if __name__ == '__main__':
    main()
