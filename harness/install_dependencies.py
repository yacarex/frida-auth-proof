"""Install the reviewed wheel payload, offline after hash-checked download."""
import hashlib
import json
import pathlib
import subprocess
import sys
import urllib.parse
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
def install(destination):
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    wheels = destination / 'wheels'
    wheels.mkdir()
    artifacts = json.loads((ROOT / 'dependency-artifacts.json').read_text())['artifacts']
    for a in artifacts:
        parsed = urllib.parse.urlsplit(a['url'])
        assert parsed.scheme == 'https' and parsed.netloc == 'files.pythonhosted.org'
        assert pathlib.Path(a['filename']).name == a['filename']
        with urllib.request.urlopen(a['url'], timeout=30) as r:
            raw = r.read()
        assert hashlib.sha256(raw).hexdigest() == a['sha256'], 'DOWNLOAD_INTEGRITY'
        (wheels / a['filename']).write_bytes(raw)
    subprocess.run([sys.executable, '-m', 'venv', '--without-pip', str(destination / 'venv')], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    py = str(destination / 'venv/bin/python')
    subprocess.run([py, '-c', 'import runpy,sys; sys.path.insert(0,sys.argv.pop(1)); runpy.run_module("pip",run_name="__main__")',
                    str(wheels / next(a['filename'] for a in artifacts if a['name'] == 'pip')),
                    '--isolated', 'install', '--no-index', '--no-cache-dir',
                    '--find-links', str(wheels), '--require-hashes', '--only-binary=:all:',
                    '-r', str(ROOT / 'requirements.lock')], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run([py, str(ROOT / 'harness/dependency_gate.py'), str(wheels)], check=True)
    subprocess.run([py, str(ROOT / 'harness/dependency_compatibility.py')], check=True)

if __name__ == '__main__':
    try:
        install(pathlib.Path(sys.argv[1]))
    except Exception:
        print('{"dependency_install":"BLOCKED"}', flush=True)
        raise SystemExit(1)
