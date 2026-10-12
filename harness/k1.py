"""K1 transport observer. No OAuth server, token repair, or refresh broker.

Runs only in the separately approved ephemeral Actions environment.
OAuthlib generates PKCE and authorization requests; PyJWT validates signatures.
Negative token requests intentionally use ordinary HTTP to preserve bad inputs.
Raw responses/HTML/headers are memory-only and are never printed.
"""
import concurrent.futures
import json
import os
import pathlib
import secrets
import threading
import time
from urllib.parse import parse_qs, urlencode, urljoin, urlsplit

import jwt
import requests
from bs4 import BeautifulSoup
from oauthlib.oauth2 import WebApplicationClient
from setup import A, B, U, BASE, CLIENT, TENANT, USER, OAUTH, JWT

class Blocked(Exception):
    pass

class Rejected(Exception):
    pass

REPORT = {'profile': 'O20-PKCE', 'candidate': 'FusionAuth 1.69.3',
          'gates': {f'K{i}': 'NOT_RUN' for i in range(1, 7)},
          'cases': [], 'transport': [], 'config_readback': 'NOT_RUN'}
LOCK = threading.Lock()
SAFE_ERRORS = {'invalid_grant', 'invalid_request', 'invalid_client',
               'unauthorized_client', 'access_denied', 'invalid_scope'}

class Wire(requests.Session):
    def __init__(self, label):
        super().__init__()
        self.label = label
        self.trust_env = False

    def send(self, request, **kwargs):
        parsed = urlsplit(request.url)
        if (parsed.scheme, parsed.netloc) != ('http', '127.0.0.1:9011'):
            raise Blocked('NON_LOOPBACK_DESTINATION')
        body = request.body or ''
        if isinstance(body, bytes):
            body = body.decode('utf-8')
        query = parse_qs(parsed.query, keep_blank_values=True)
        values = parse_qs(body, keep_blank_values=True) if request.method == 'POST' else query
        record = None
        if parsed.path in ('/oauth2/authorize', '/oauth2/token'):
            record = {'case': self.label, 'method': request.method,
                      'path': parsed.path, 'sent_monotonic': time.monotonic()}
            for field in ('redirect_uri', 'client_id', 'response_type', 'grant_type',
                          'scope', 'code_challenge_method'):
                record[field] = values.get(field, [])
            for field in ('code', 'code_verifier', 'code_challenge', 'state', 'nonce', 'client_secret'):
                record[field + '_present'] = field in values
            record['authorization_header_present'] = 'Authorization' in request.headers
        kwargs['allow_redirects'] = False
        kwargs['timeout'] = 15
        response = super().send(request, **kwargs)
        if record is not None:
            record['received_monotonic'] = time.monotonic()
            record['status'] = response.status_code
            with LOCK:
                REPORT['transport'].append(record)
        return response

def must(condition, reason):
    if not condition:
        raise Blocked(reason)

def readback(credentials):
    session = Wire('readback')
    session.headers.update({'Authorization': credentials['api_key'], 'X-FusionAuth-TenantId': TENANT})
    app = session.get(BASE + '/api/application/' + CLIENT)
    tenant = session.get(BASE + '/api/tenant/' + TENANT)
    must(app.status_code == tenant.status_code == 200, 'CONFIG_READBACK_HTTP')
    app = app.json()['application']
    tenant = tenant.json()['tenant']
    for key, value in OAUTH.items():
        got = app['oauthConfiguration'].get(key)
        must(sorted(got) == sorted(value) if isinstance(value, list) and isinstance(got, list)
             else got == value, 'OAUTH_CONFIG_MISMATCH')
    for key, value in JWT.items():
        must(app['jwtConfiguration'].get(key) == value, 'JWT_CONFIG_MISMATCH')
    must(tenant['externalIdentifierConfiguration']['authorizationGrantIdTimeToLiveInSeconds'] == 60,
         'CODE_TTL_MISMATCH')
    must(tenant['jwtConfiguration']['refreshTokenRevocationPolicy']['onOneTimeTokenReuse'] is True,
         'REUSE_CONFIG_MISMATCH')
    must(tenant['issuer'] == BASE, 'ISSUER_CONFIG_MISMATCH')
    # Exact allowlist; app object may contain an auto-generated client secret:
    # it is never used, printed or copied into Native requests.
    REPORT['config_readback'] = {'oauth': OAUTH, 'jwt': JWT, 'code_seconds': 60,
                                 'issuer': BASE, 'native_secret_used': False}

def authorize(label, credentials, redirect=A):
    client = WebApplicationClient(CLIENT)
    verifier = client.create_code_verifier(64)
    challenge = client.create_code_challenge(verifier, 'S256')
    state, nonce = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    url = client.prepare_request_uri(BASE + '/oauth2/authorize', redirect_uri=redirect,
            scope=['openid', 'offline_access'], state=state, nonce=nonce,
            code_challenge=challenge, code_challenge_method='S256')
    session = Wire(label)
    response = session.get(url)
    for _ in range(12):
        if response.is_redirect:
            target = urljoin(response.url, response.headers['Location'])
            parts = urlsplit(target)
            if parts.netloc == 'callback.proof.invalid':
                actual = parts._replace(query='', fragment='').geturl()
                must(actual == redirect, 'CALLBACK_MISMATCH')
                values = parse_qs(parts.query)
                must(values.get('state') == [state], 'STATE_MISMATCH')
                if values.get('error'):
                    return None
                must(len(values.get('code', [])) == 1, 'CODE_MISSING')
                return {'code': values['code'][0], 'verifier': verifier, 'nonce': nonce,
                        'received': time.monotonic()}
            response = session.get(target)
            continue
        if response.status_code >= 500 or response.status_code == 429:
            raise Blocked('AUTHORIZATION_INFRASTRUCTURE')
        soup = BeautifulSoup(response.text, 'html.parser')
        form = next((f for f in soup.find_all('form') if f.find('input', {'name': 'loginId'})), None)
        if form is None:
            # A generic HTML page is NOT a normative rejection oracle.
            raise Blocked('AUTHORIZATION_FORM_OR_ERROR_UNCLASSIFIED')
        fields = {i['name']: i.get('value', '') for i in form.find_all('input') if i.get('name')}
        fields.update(loginId='fixture@example.invalid', password=credentials['password'])
        must(form.get('method', 'get').lower() == 'post', 'LOGIN_FORM_METHOD')
        response = session.post(urljoin(response.url, form.get('action', '')), data=fields)
    raise Blocked('AUTHORIZATION_STEP_LIMIT')

def exchange(label, attempt, redirect=A, barrier=None):
    session = Wire(label)
    data = {'grant_type': 'authorization_code', 'client_id': CLIENT,
            'code': attempt['code'], 'code_verifier': attempt['verifier']}
    if redirect is not None:
        data['redirect_uri'] = redirect
    request = session.prepare_request(requests.Request('POST', BASE + '/oauth2/token', data=data))
    if barrier:
        barrier.wait(timeout=10)
    response = session.send(request)
    try:
        payload = response.json()
    except ValueError:
        raise Blocked('NON_JSON_TOKEN_RESPONSE') from None
    issued = any(isinstance(payload.get(k), str) and payload[k] for k in ('access_token', 'id_token', 'refresh_token'))
    verified = False
    if issued and payload.get('id_token'):
        try:
            jwks = session.get(BASE + '/.well-known/jwks.json')
            must(jwks.status_code == 200, 'JWKS_UNAVAILABLE')
            header = jwt.get_unverified_header(payload['id_token'])
            must(header.get('alg') == 'RS256', 'UNEXPECTED_ALGORITHM')
            key = next(k for k in jwks.json()['keys'] if k.get('kid') == header.get('kid'))
            claims = jwt.decode(payload['id_token'], jwt.PyJWK.from_dict(key).key,
                     algorithms=['RS256'], audience=CLIENT, issuer=BASE,
                     options={'require': ['sub', 'exp', 'iat', 'aud', 'iss', 'nonce']})
            verified = claims['nonce'] == attempt['nonce'] and claims['sub'] == USER
        except Exception:
            verified = False
    error = payload.get('error')
    error = error if error in SAFE_ERRORS else ('OTHER' if error else None)
    result = {'case': label, 'http': response.status_code, 'token_issued': bool(issued),
              'id_token_verified': verified, 'error': error}
    with LOCK:
        REPORT['cases'].append(result)
    return result

def positive(result):
    must(result['http'] == 200 and result['token_issued'] and result['id_token_verified'], 'CONTROL_NOT_VALID')

def negative(result):
    if result['token_issued']:
        REPORT['gates']['K1'] = 'FAIL'
        raise Rejected('INVALID_EXCHANGE_ISSUED_TOKEN')
    must(result['http'] in (400, 401) and result['error'] in SAFE_ERRORS, 'NEGATIVE_INCONCLUSIVE')

def run(credentials):
    readback(credentials)
    attempt = authorize('A_to_A', credentials)
    must(attempt is not None, 'CONTROL_CODE_NOT_ISSUED')
    positive(exchange('A_to_A', attempt))
    for label, redirect in [('B_registered', B), ('B_unregistered', U),
                            ('redirect_absent', None), ('query_variation', A + '?variant=1')]:
        attempt = authorize(label, credentials)
        must(attempt is not None, 'NEGATIVE_CODE_NOT_ISSUED')
        negative(exchange(label, attempt, redirect))
    attempt = authorize('one_use', credentials)
    must(attempt is not None, 'REPLAY_CONTROL_NO_CODE')
    positive(exchange('one_use_first', attempt))
    negative(exchange('one_use_replay', attempt))
    attempt = authorize('double_exchange', credentials)
    must(attempt is not None, 'CONCURRENT_CONTROL_NO_CODE')
    barrier = threading.Barrier(2)
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(exchange, f'double_exchange_{i}', attempt, A, barrier) for i in range(2)]
        results = [f.result() for f in futures]
    issued = [r for r in results if r['token_issued']]
    if len(issued) > 1:
        REPORT['gates']['K1'] = 'FAIL'
        raise Rejected('DOUBLE_EXCHANGE_TWO_ISSUANCES')
    must(len(issued) == 1, 'CONCURRENT_NO_WINNER')
    positive(issued[0])
    for r in results:
        if not r['token_issued']:
            negative(r)
    attempt = authorize('expiry', credentials)
    must(attempt is not None, 'EXPIRY_CONTROL_NO_CODE')
    # Real AS time. 60-second readback + >60 elapsed since receipt of code.
    remaining = 61 - (time.monotonic() - attempt['received'])
    if remaining > 0:
        time.sleep(remaining)
    REPORT['expiry_elapsed_seconds'] = time.monotonic() - attempt['received']
    negative(exchange('expiry', attempt))
    # Registration rejection is a distinct contract. Require a structured
    # rejection; generic pages remain UNKNOWN instead of passing silently.
    attempt = authorize('authorization_unregistered', credentials, U)
    if attempt is not None:
        REPORT['gates']['K1'] = 'FAIL'
        raise Rejected('UNREGISTERED_CALLBACK_RECEIVED_CODE')
    REPORT['gates']['K1'] = 'PASS'
    REPORT['result'] = 'K1_PASS_ONLY'

def main():
    credentials = json.loads((pathlib.Path(os.environ['PROOF_PRIVATE']) / 'credentials.json').read_text())
    try:
        run(credentials)
    except Rejected as exc:
        REPORT['result'] = 'FUSIONAUTH REJECTED'
        REPORT['reason'] = exc.args[0]
    except Blocked as exc:
        REPORT['result'] = 'FUSIONAUTH PROOF BLOCKED'
        REPORT['reason'] = exc.args[0]
    except Exception:
        # Tracebacks/exception messages can contain URLs, codes and bodies.
        REPORT['result'] = 'FUSIONAUTH PROOF BLOCKED'
        REPORT['reason'] = 'UNCLASSIFIED_HARNESS_OR_INFRASTRUCTURE_ERROR'
    report = json.dumps(REPORT, sort_keys=True)
    print(report)
    summary = os.environ.get('GITHUB_STEP_SUMMARY')
    if summary:
        with open(summary, 'a') as out:
            out.write('```json\n' + report + '\n```\n')
    return 0 if REPORT['gates']['K1'] == 'PASS' else 1

if __name__ == '__main__':
    raise SystemExit(main())
