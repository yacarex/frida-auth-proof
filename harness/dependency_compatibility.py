"""Offline import/API smoke checks only. No AS, network, or K1 execution."""
import json
import time
from urllib.parse import parse_qs, urlsplit
import jwt
import requests
from bs4 import BeautifulSoup
from cryptography.hazmat.primitives.asymmetric import rsa
from oauthlib.oauth2 import WebApplicationClient

def run():
    client = WebApplicationClient('synthetic-client')
    verifier = client.create_code_verifier(64)
    challenge = client.create_code_challenge(verifier, 'S256')
    url = client.prepare_request_uri('https://as.example.invalid/oauth2/authorize',
          redirect_uri='https://app.example.invalid/callback', scope=['openid','offline_access'],
          state='synthetic-state', nonce='synthetic-nonce', code_challenge=challenge,
          code_challenge_method='S256')
    query = parse_qs(urlsplit(url).query)
    assert query['code_challenge_method'] == ['S256'] and query['nonce'] == ['synthetic-nonce']
    assert query['redirect_uri'] == ['https://app.example.invalid/callback']
    with requests.Session() as session:
        request = session.prepare_request(requests.Request('POST','https://as.example.invalid/oauth2/token',
            data={'grant_type':'authorization_code','client_id':'synthetic-client','code':'synthetic-only'}))
        assert 'client_secret' not in request.body
    soup = BeautifulSoup('<form action="/login"><input name="loginId"><input name="password"></form>', 'html.parser')
    assert soup.find('form').get('action') == '/login'
    assert len(soup.select('input[name]')) == 2
    # Ephemeral memory-only key/token. Neither is returned, logged, or exported.
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk['kid'] = 'synthetic-key'
    now = int(time.time())
    claims = dict(sub='synthetic-user',exp=now+60,iat=now,aud='synthetic-client',
                  iss='https://as.example.invalid',nonce='synthetic-nonce')
    token = jwt.encode(claims,key,algorithm='RS256',headers={'kid':'synthetic-key'})
    assert jwt.get_unverified_header(token)['alg'] == 'RS256'
    decoded = jwt.decode(token,jwt.PyJWK.from_dict(jwk).key,algorithms=['RS256'],
          audience='synthetic-client',issuer='https://as.example.invalid',
          options={'require':['sub','exp','iat','aud','iss','nonce']})
    assert decoded == claims
    import k1  # import only: __main__ and run are deliberately not called
    assert issubclass(k1.Wire,requests.Session)
    print(json.dumps({'dependency_imports':'PASS','oauthlib_client_API':'PASS',
        'requests_preparation':'PASS','html_parser_selector':'PASS','PyJWT_RS256_JWK':'PASS',
        'harness_import':'PASS','AS_requests':0,'K1':'NOT_RUN'}))

if __name__ == '__main__':
    try:
        run()
    except Exception:
        print('{"dependency_compatibility":"BLOCKED"}')
        raise SystemExit(1)
