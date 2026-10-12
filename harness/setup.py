"""Ephemeral FusionAuth configuration; never print API responses or secrets."""
import json
import os
import pathlib
import secrets

BASE = 'http://127.0.0.1:9011'
A = 'https://callback.proof.invalid/native/a'
B = 'https://callback.proof.invalid/native/b'
U = 'https://callback.proof.invalid/unregistered'
TENANT = '11111111-1111-4111-8111-111111111111'
CLIENT = '22222222-2222-4222-8222-222222222222'
USER = '33333333-3333-4333-8333-333333333333'
KEY = '44444444-4444-4444-8444-444444444444'

JWT = {
    'accessTokenKeyId': KEY, 'idTokenKeyId': KEY,
    'timeToLiveInSeconds': 300,
    'refreshTokenExpirationPolicy': 'SlidingWindowWithMaximumLifetime',
    'refreshTokenTimeToLiveInMinutes': 10080,
    'refreshTokenSlidingWindowConfiguration': {'maximumTimeToLiveInMinutes': 43200},
    'refreshTokenUsagePolicy': 'OneTimeUse',
    'refreshTokenOneTimeUseConfiguration': {'gracePeriodInSeconds': 0},
}
OAUTH = {
    'clientAuthenticationPolicy': 'NotRequired',
    'proofKeyForCodeExchangePolicy': 'Required',
    'authorizedURLValidationPolicy': 'ExactMatch',
    'authorizedRedirectURLs': [A, B],
    'enabledGrants': ['authorization_code', 'refresh_token'],
    'generateRefreshTokens': True, 'requireRegistration': True,
    'relationship': 'FirstParty', 'debug': False,
}

def prepare(folder):
    folder = pathlib.Path(folder)
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    api_key = secrets.token_urlsafe(48)
    password = secrets.token_urlsafe(48)
    credentials = {'api_key': api_key, 'password': password}
    def req(url, body, tenant=False):
        value = {'method': 'POST', 'url': url, 'body': body}
        if tenant:
            value['tenantId'] = TENANT
        return value
    kickstart = {'apiKeys': [{'key': api_key}], 'requests': [
        req('/api/key/generate/' + KEY, {'key': {
            'algorithm': 'RS256', 'name': 'Synthetic signing key', 'length': 2048}}),
        req('/api/tenant/' + TENANT, {'tenant': {
            'name': 'Synthetic isolated proof', 'issuer': BASE,
            'externalIdentifierConfiguration': {'authorizationGrantIdTimeToLiveInSeconds': 60},
            'jwtConfiguration': dict(JWT, refreshTokenRevocationPolicy={'onOneTimeTokenReuse': True})}}),
        req('/api/application/' + CLIENT, {'application': {
            'name': 'Synthetic Native public client', 'oauthConfiguration': OAUTH,
            'jwtConfiguration': dict(JWT, enabled=True)}}, True),
        req('/api/user/registration/' + USER, {
            'user': {'email': 'fixture@example.invalid', 'password': password},
            'registration': {'applicationId': CLIENT}}, True),
    ]}
    # Password is ONLY a synthetic login fixture for protocol K1, not a
    # passwordless, verification, recovery, signup, or consumer-UX PASS.
    (folder / 'credentials.json').write_text(json.dumps(credentials))
    (folder / 'kickstart.json').write_text(json.dumps(kickstart))
    env = {
        'DATABASE_URL': 'jdbc:postgresql://postgres:5432/fusionauth',
        'DATABASE_ROOT_USERNAME': 'postgres',
        'DATABASE_ROOT_PASSWORD': secrets.token_urlsafe(32),
        'DATABASE_USERNAME': 'fusionauth',
        'DATABASE_PASSWORD': secrets.token_urlsafe(32),
        'FUSIONAUTH_APP_RUNTIME_MODE': 'development',
        'FUSIONAUTH_APP_SILENT_MODE': 'true',
        'FUSIONAUTH_APP_KICKSTART_FILE': '/proof/kickstart.json',
        'SEARCH_TYPE': 'database',
    }
    (folder / 'container.env').write_text(''.join(k+'='+v+'\n' for k,v in env.items()))
    # Docker image may run non-root; only kickstart is readable inside its
    # read-only bind mount. Parent directory stays private on runner.
    (folder / 'kickstart.json').chmod(0o644)
    for name in ('credentials.json', 'container.env'):
        (folder / name).chmod(0o600)

if __name__ == '__main__':
    prepare(os.environ['PROOF_PRIVATE'])
