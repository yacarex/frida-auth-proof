"""Dependency-only gate; never imports or starts the AS/K1.

Audit source: PyPI release-specific OSV advisory feed. Every installed distribution
is checked; missing metadata/network errors or any active advisory fail closed.
"""
import concurrent.futures
import hashlib
import importlib.metadata
import json
import pathlib
import platform
import re
import subprocess
import sys
import urllib.request
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
def canonical(name):
    return re.sub(r'[-_.]+', '-', name).lower()

def verify(wheels):
    assert sys.version_info[:2] == (3, 12), 'PYTHON_VERSION'
    assert platform.system() == 'Linux' and platform.machine() == 'x86_64', 'PLATFORM'
    artifacts = json.loads((ROOT / 'dependency-artifacts.json').read_text())['artifacts']
    expected = {canonical(a['name']): a for a in artifacts}
    distributions = list(importlib.metadata.distributions())
    installed = {canonical(d.metadata['Name']): d for d in distributions}
    assert len(installed) == len(distributions) and set(installed) == set(expected), 'GRAPH_MISMATCH'
    assert {p.name for p in wheels.iterdir()} == {a['filename'] for a in artifacts}, 'ARTIFACT_SET'
    checked = 0
    for name, a in expected.items():
        d = installed[name]
        assert d.version == a['version'], 'VERSION_MISMATCH'
        wheel = wheels / a['filename']
        assert hashlib.sha256(wheel.read_bytes()).hexdigest() == a['sha256'], 'ARTIFACT_HASH'
        # Compare installed immutable payload directly with authenticated wheel.
        # RECORD is rewritten by pip; generated pyc/scripts are not wheel payload.
        with zipfile.ZipFile(wheel) as z:
            for member in z.namelist():
                if member.endswith('/') or member.endswith('.dist-info/RECORD'):
                    continue
                assert '.data/' not in member, 'UNSUPPORTED_WHEEL_LAYOUT'
                assert d.locate_file(member).read_bytes() == z.read(member), 'INSTALLED_PAYLOAD_HASH'
                checked += 1
    subprocess.run([sys.executable, '-m', 'pip', 'check'], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    def audit(item):
        name, d = item
        url = 'https://pypi.org/pypi/' + name + '/' + d.version + '/json'
        with urllib.request.urlopen(url, timeout=30) as r:
            raw = r.read()
        data = json.loads(raw)
        assert canonical(data['info']['name']) == name and data['info']['version'] == d.version
        assert isinstance(data['vulnerabilities'], list), 'ADVISORY_DATA_MISSING'
        active = [a['id'] for a in data['vulnerabilities'] if not a.get('withdrawn')]
        return {'name':name, 'version':d.version, 'source':url,
                'metadata_sha256':hashlib.sha256(raw).hexdigest(), 'active_advisories':active}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        rows = list(pool.map(audit, sorted(installed.items())))
    result = {'scope':'complete installed Python distribution graph, including pip',
              'audit_source':'PyPI release-specific OSV feed', 'packages':rows,
              'findings':sum(len(r['active_advisories']) for r in rows),
              'wheel_sha256':'PASS','installed_payload_files_verified':checked,
              'dependency_consistency':'PASS','K1':'NOT_RUN'}
    print(json.dumps(result, sort_keys=True), flush=True)
    assert result['findings'] == 0, 'DEPENDENCY_SECURITY'

if __name__ == '__main__':
    try:
        verify(pathlib.Path(sys.argv[1]))
    except Exception:
        print('{"dependency_gate":"BLOCKED"}', flush=True)
        raise SystemExit(1)
