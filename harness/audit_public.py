"""Static publication inventory and denylist. Never executes the AS/proof."""
import hashlib
import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]

def audit():
    inventory = json.loads((ROOT / 'PUBLIC_INVENTORY.json').read_text())
    expected = {entry['path']: entry['sha256'] for entry in inventory['files']}
    actual = {p.relative_to(ROOT).as_posix(): p for p in ROOT.rglob('*')
              if p.is_file() and '.git' not in p.relative_to(ROOT).parts
              and '__pycache__' not in p.relative_to(ROOT).parts}
    assert set(actual) == set(expected) | {'PUBLIC_INVENTORY.json'}, 'UNREVIEWED_FILES'
    denied = [r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
              r'gh[pousr]_[A-Za-z0-9]{30,}', r'github_pat_[A-Za-z0-9_]{30,}',
              r'eyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}']
    for name, digest in expected.items():
        p = actual[name]
        assert not p.is_symlink(), 'SYMLINK'
        raw = p.read_bytes()
        assert hashlib.sha256(raw).hexdigest() == digest, 'CONTENT_CHANGED'
        text = raw.decode('utf-8')
        assert not any(re.search(pattern, text) for pattern in denied), 'SECRET_PATTERN'
        assert not any(part == '.env' or part.startswith('.env.') for part in p.parts), 'ENV_FILE'
    matrix = (ROOT / 'docs/NORMATIVE_MATRIX.md').read_text()
    assert set(re.findall(r'^\| (N\d{2}) \|', matrix, re.M)) == {f'N{i:02}' for i in range(1,55)}
    workflow = (ROOT / '.github/workflows/fusionauth-k1.yml').read_text()
    assert '\n  workflow_dispatch:' in workflow
    assert not re.search(r'^\s*(push|pull_request|pull_request_target|schedule|workflow_run):', workflow, re.M)
    assert 'runs-on: ubuntu-24.04' in workflow
    assert not any(x in workflow for x in ['secrets.', 'upload-artifact', 'actions/cache', 'self-hosted'])
    print(json.dumps({'static_inventory': 'PASS', 'files': len(expected),
                      'secret_patterns': 'NO_MATCH', 'requirements': 54,
                      'runtime': 'NOT_RUN', 'manual_review_required': True}))

if __name__ == '__main__':
    audit()
