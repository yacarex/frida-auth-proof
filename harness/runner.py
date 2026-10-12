"""Lifecycle only. No services are started while preparing this repository."""
import json
import os
import pathlib
import shutil
import subprocess
import sys
import time
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
NAME = 'frida-proof-' + os.environ.get('GITHUB_RUN_ID', 'invalid') + '-' + os.environ.get('GITHUB_RUN_ATTEMPT', '0')
PRIVATE = pathlib.Path(os.environ.get('RUNNER_TEMP', '/invalid')) / NAME

def command(args, capture=False, **kwargs):
    return subprocess.run(args, check=True, stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, **kwargs)

def cleanup():
    # Only resources created by this workflow, never Docker-wide prune.
    subprocess.run(['docker', 'rm', '-fv', NAME], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    pg = os.environ.get('PROOF_POSTGRES_ID', '')
    if pg:
        subprocess.run(['docker', 'rm', '-fv', pg], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    shutil.rmtree(PRIVATE, ignore_errors=True)
    remaining = command(['docker', 'ps', '-aq', '--filter', 'name=^/' + NAME + '$'], True).stdout.strip()
    pg_absent = True
    if pg:
        r = subprocess.run(['docker', 'inspect', pg], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        pg_absent = r.returncode != 0
    result = {'fusionauth_absent': not bool(remaining), 'postgres_absent': pg_absent,
              'private_directory_absent': not PRIVATE.exists()}
    print('CLEANUP ' + json.dumps(result))
    if not all(result.values()):
        raise RuntimeError('CLEANUP_NOT_COMPLETE')

def run():
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('GITHUB_REPOSITORY') != 'yacarex/frida-auth-proof':
        raise RuntimeError('ISOLATED_ACTIONS_ONLY')
    manifest = json.loads((ROOT / 'manifest.json').read_text())
    pg = os.environ['PROOF_POSTGRES_ID']
    network = json.loads(command(['docker', 'inspect', pg], True).stdout)[0]['NetworkSettings']['Networks']
    if len(network) != 1:
        raise RuntimeError('SERVICE_NETWORK_AMBIGUOUS')
    PRIVATE.mkdir(mode=0o700)
    # OAuthlib accepts HTTP only for this loopback-only synthetic AS. Wire
    # independently denies every destination except 127.0.0.1:9011.
    env = dict(os.environ, PROOF_PRIVATE=str(PRIVATE), PIP_DISABLE_PIP_VERSION_CHECK='1',
               OAUTHLIB_INSECURE_TRANSPORT='1')
    # This dependency-only barrier prints allowlisted audit/integrity results.
    # Failure prevents fixture creation, FusionAuth startup and every K1 request.
    subprocess.run([sys.executable, str(ROOT / 'harness/install_dependencies.py'),
                    str(PRIVATE)], check=True, timeout=300, stderr=subprocess.DEVNULL)
    py = str(PRIVATE / 'venv/bin/python')
    command([py, str(ROOT / 'harness/setup.py')], env=env)
    image = manifest['images']['fusionauth']
    command(['docker', 'pull', image], timeout=180)
    command(['docker', 'run', '-d', '--name', NAME, '--log-driver', 'none',
             '--network', next(iter(network)), '-p', '127.0.0.1:9011:9011',
             '--env-file', str(PRIVATE / 'container.env'),
             '-v', str(PRIVATE / 'kickstart.json') + ':/proof/kickstart.json:ro', image])
    ready = False
    for _ in range(90):
        try:
            with urllib.request.urlopen('http://127.0.0.1:9011/api/status', timeout=2) as r:
                if r.status == 200:
                    ready = True
                    break
        except Exception:
            pass
        time.sleep(2)
    if not ready:
        raise RuntimeError('AS_STARTUP_BLOCKED')
    # Child prints only its own allowlisted JSON; stderr never published.
    result = subprocess.run([py, str(ROOT / 'harness/k1.py')], env=env, stderr=subprocess.DEVNULL)
    return result.returncode

if __name__ == '__main__':
    if sys.argv[1:] == ['cleanup']:
        cleanup()
    else:
        result = 1
        try:
            result = run()
        except Exception:
            print('FUSIONAUTH PROOF BLOCKED: EXECUTOR_SETUP_OR_DEPENDENCY_ERROR')
        finally:
            cleanup()
        raise SystemExit(result)
