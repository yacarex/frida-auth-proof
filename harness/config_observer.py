"""Read-only configuration diagnostics. Never emits response values or headers."""
import time

CATEGORIES = {200:'OK', 400:'INVALID_REQUEST_OR_CONFIGURATION',
              401:'AUTHENTICATION_OR_SCOPE_DENIED',403:'FORBIDDEN',404:'RESOURCE_NOT_FOUND',
              429:'RATE_LIMITED',500:'SERVER_ERROR',502:'UPSTREAM_ERROR',503:'SERVICE_UNAVAILABLE'}

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
