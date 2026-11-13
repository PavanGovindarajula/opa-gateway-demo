"""Run against the Compose stack, including the real OPA policy engine."""
import json
from urllib.error import HTTPError
from urllib.request import Request, urlopen


def call(port, payload):
    request = Request(f'http://127.0.0.1:{port}/v1/tools/invoke', data=json.dumps(payload).encode(), headers={'Content-Type': 'application/json'})
    try:
        with urlopen(request, timeout=5) as response:
            return response.status, json.load(response)
    except HTTPError as error:
        return error.code, json.load(error)


base = {'tool': 'search_documents', 'classification': 'internal', 'destination': '', 'roles': []}
for port in (8081, 8082):
    status, result = call(port, base)
    assert status == 200 and result['policy_decision'] == 'allow' and result['simulated_execution']
blocked = dict(base, tool='export_documents', classification='restricted', roles=['reviewer'])
status, dry = call(8081, blocked)
assert status == 200 and dry['policy_decision'] == 'deny' and dry['simulated_execution']
status, enforce = call(8082, blocked)
assert status == 403 and enforce['policy_decision'] == 'deny' and not enforce['simulated_execution']
assert dry['reasons'] == enforce['reasons'] == ['restricted data cannot be exported']
print('Real OPA integration: allow, dry-run, and enforce passed')
