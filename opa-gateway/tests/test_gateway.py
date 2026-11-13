import importlib.util
import io
import json
import unittest
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('gateway', Path(__file__).resolve().parents[1] / 'gateway.py')
gateway = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gateway)
REQUEST = {'tool': 'export_documents', 'classification': 'restricted', 'destination': '', 'roles': ['reviewer']}
DENY = {'allow': False, 'reasons': ['restricted data cannot be exported']}
ALLOW = {'allow': True, 'reasons': []}


class Response(io.BytesIO):
    pass


class GatewayTests(unittest.TestCase):
    def test_opa_protocol(self):
        with patch.object(gateway, 'urlopen', return_value=Response(json.dumps({'result': DENY}).encode())) as opener:
            self.assertEqual(gateway.evaluate('http://opa:8181', REQUEST), DENY)
            request = opener.call_args.args[0]
            self.assertEqual(request.full_url, 'http://opa:8181/v1/data/toolrisk/decision')
            self.assertEqual(json.loads(request.data), {'input': REQUEST})

    def test_dry_run_and_enforce(self):
        self.assertTrue(gateway.process(REQUEST, 'dry-run', lambda _: DENY)['simulated_execution'])
        self.assertFalse(gateway.process(REQUEST, 'enforce', lambda _: DENY)['simulated_execution'])
        self.assertTrue(gateway.process(REQUEST, 'enforce', lambda _: ALLOW)['simulated_execution'])

    def test_unknown_tool_or_classification_never_dispatched(self):
        for value in (dict(REQUEST, tool='shell'), dict(REQUEST, classification='secret')):
            self.assertFalse(gateway.process(value, 'dry-run', lambda _: DENY)['simulated_execution'])

    def test_invalid_payload(self):
        for value in ({}, dict(REQUEST, roles='reviewer'), dict(REQUEST, extra=True)):
            with self.assertRaises(ValueError):
                gateway.process(value, 'enforce', lambda _: ALLOW)

    def test_invalid_opa_response_and_unavailable(self):
        for payload in ({}, {'result': {'allow': 'true', 'reasons': []}}, {'result': {'allow': False, 'reasons': []}}):
            with patch.object(gateway, 'urlopen', return_value=Response(json.dumps(payload).encode())):
                with self.assertRaises(RuntimeError):
                    gateway.evaluate('http://opa', REQUEST)
        with patch.object(gateway, 'urlopen', side_effect=OSError('connection failed')):
            with self.assertRaises(RuntimeError):
                gateway.evaluate('http://opa', REQUEST)


if __name__ == '__main__':
    unittest.main()
