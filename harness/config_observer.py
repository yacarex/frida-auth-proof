"""Read-only configuration diagnostics. Never emits response values or headers."""
import time

CATEGORIES = {200:'OK', 400:'INVALID_REQUEST_OR_CONFIGURATION',
              401:'AUTHENTICATION_OR_SCOPE_DENIED',403:'FORBIDDEN',404:'RESOURCE_NOT_FOUND',
              429:'RATE_LIMITED',500:'SERVER_ERROR',502:'UPSTREAM_ERROR',503:'SERVICE_UNAVAILABLE'}

# Closed diagnostic vocabulary, NOT an audit/security exception list. Unknown
# server strings are never copied, even when they look like harmless identifiers.
SAFE_FIELDS = frozenset({'tenantId', 'applicationId', 'id', 'X-FusionAuth-TenantId',
    'Authorization', 'apiKey', 'apiKey.key', 'apiKey.tenantId', 'tenant.id',
    'application.id', 'application.tenantId'})
ERROR_KINDS = {
    '[invalid]':'INVALID_VALUE', '[missing]':'MISSING_VALUE',
    '[required]':'REQUIRED_VALUE', '[blank]':'BLANK_VALUE',
    '[notFound]':'NOT_FOUND', '[duplicate]':'DUPLICATE',
    '[invalidUUID]':'INVALID_UUID', '[invalidJSON]':'INVALID_JSON',
    '[unauthorized]':'AUTHORIZATION', '[forbidden]':'AUTHORIZATION',
    '[TenantIdRequired]':'TENANT_REQUIRED', '[InvalidTenantId]':'INVALID_TENANT',
    '[invalidTenantId]':'INVALID_TENANT', '[invalidAPIKey]':'INVALID_API_KEY',
    '[invalidApiKey]':'INVALID_API_KEY', '[invalidHeader]':'INVALID_HEADER',
    '[invalidLicense]':'LICENSE', '[licenseRequired]':'LICENSE',
}
SAFE_CODES = {prefix + suffix: category for prefix, category in ERROR_KINDS.items()
              for suffix in ('', *sorted(SAFE_FIELDS))}

def structured_errors(body):
    result = {'field_errors_present':'fieldErrors' in body,
              'general_errors_present':'generalErrors' in body,
              'messages':'OMITTED_UNCONDITIONALLY', 'errors':[],
              'truncated':False, 'malformed':False}
    def add(scope, field, error):
        if len(result['errors']) >= 16:
            result['truncated'] = True
            return
        if not isinstance(error,dict):
            result['malformed'] = True
            return
        code = error.get('code')
        known = isinstance(code,str) and code in SAFE_CODES
        result['errors'].append({'scope':scope,
            'field':field if isinstance(field,str) and field in SAFE_FIELDS else
                    ('NOT_APPLICABLE' if scope == 'general' else 'UNREVIEWED_FIELD'),
            'code':code if known else 'UNREVIEWED_CODE',
            'validation_category':SAFE_CODES[code] if known else 'UNKNOWN',
            'message_present':'message' in error})
    fields = body.get('fieldErrors', {})
    if isinstance(fields,dict):
        for index,(field,errors) in enumerate(fields.items()):
            if index >= 16:
                result['truncated'] = True
                break
            if isinstance(errors,list):
                for error in errors[:16]: add('field',field,error)
                result['truncated'] |= len(errors) > 16
            else: result['malformed'] = True
    else: result['malformed'] = True
    general = body.get('generalErrors', [])
    if isinstance(general,list):
        for error in general[:16]: add('general',None,error)
        result['truncated'] |= len(general) > 16
    else: result['malformed'] = True
    return result

def observe(session, base, resources, records, attempts=5, sleep=time.sleep):
    """Bounded readiness only, before OAuth cases. No writes/repair/fallback key."""
    responses = {}
    for attempt in range(1, attempts + 1):
        for label, path, object_key, expected_id in resources:
            record = {'resource':label,'method':'GET','path':path,'attempt':attempt}
            try:
                response = session.get(base + path)
            except Exception:
                record.update(http_status=None, category='TRANSPORT_ERROR', body='UNAVAILABLE')
                records.append(record)
                return None
            status = response.status_code
            record.update(http_status=status, category=CATEGORIES.get(status,'OTHER_HTTP_STATUS'))
            try:
                body = response.json()
                record['body'] = 'JSON_OBJECT' if isinstance(body,dict) else 'JSON_OTHER'
            except ValueError:
                body = None
                record['body'] = 'EMPTY' if not response.content else 'NON_JSON'
            if isinstance(body,dict):
                value = body.get(object_key)
                record['expected_object_present'] = isinstance(value,dict)
                record['expected_id_matches'] = isinstance(value,dict) and value.get('id') == expected_id
                record['structured_errors_present'] = any(k in body for k in ('fieldErrors','generalErrors'))
                if status == 400:
                    record['validation'] = structured_errors(body)
            records.append(record)
            responses[label] = response
        if all(r.status_code == 200 for r in responses.values()):
            return responses
        # Never retry authorization, malformed request, rate limit or unknown error.
        if any(r.status_code not in (200,404,503) for r in responses.values()):
            return None
        if attempt < attempts:
            sleep(2)
    return None
