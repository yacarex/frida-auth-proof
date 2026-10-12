"""Dependency barrier negatives only; no provider requests."""
import contextlib
import io
import json
import pathlib
import tempfile
import unittest
from unittest.mock import patch
import dependency_gate as gate
import install_dependencies as installer

WHEELS = None
class GateTests(unittest.TestCase):
    def test_download_hash_mismatch_prevents_install(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(installer.urllib.request, 'urlopen', return_value=io.BytesIO(b'corrupt-wheel')):
                with self.assertRaisesRegex(AssertionError, 'DOWNLOAD_INTEGRITY'):
                    installer.install(pathlib.Path(directory))
            self.assertFalse((pathlib.Path(directory) / 'venv').exists())

    def test_installed_payload_tampering(self):
        d = gate.importlib.metadata.distribution('oauthlib')
        file = pathlib.Path(d.locate_file('oauthlib/__init__.py'))
        original = file.read_bytes()
        try:
            file.write_bytes(original + b'\n# integrity negative\n')
            with self.assertRaisesRegex(AssertionError,'INSTALLED_PAYLOAD_HASH'):
                gate.verify(WHEELS)
        finally:
            file.write_bytes(original)

    def test_audit_outage_fails_closed(self):
        with patch.object(gate.urllib.request,'urlopen',side_effect=TimeoutError):
            with self.assertRaises(TimeoutError):
                gate.verify(WHEELS)

    def test_any_advisory_fails_closed(self):
        def response(url, **kwargs):
            name, version = url.split('/')[-3:-1]
            return io.BytesIO(json.dumps({'info':{'name':name,'version':version},
                'vulnerabilities':[{'id':'SYNTHETIC-ADVISORY','withdrawn':None}]}).encode())
        with patch.object(gate.urllib.request,'urlopen',side_effect=response), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(AssertionError,'DEPENDENCY_SECURITY'):
                gate.verify(WHEELS)

if __name__ == '__main__':
    import sys
    WHEELS = pathlib.Path(sys.argv.pop(1))
    unittest.main()
