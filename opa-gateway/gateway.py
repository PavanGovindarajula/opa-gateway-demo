"""Demonstration policy enforcement point. All tool execution is simulated."""
import json
import logging
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import URLError
from urllib.request import Request, urlopen

MAX_BODY = 16_384
TOOLS = {'search_documents', 'export_documents', 'delete_documents', 'send_external'}
CLASSIFICATIONS = {'public', 'internal', 'restricted'}


def validate(value):
    if not isinstance(value, dict) or set(value) != {'tool', 'classification', 'destination', 'roles'}:
        raise ValueError('Expected exactly tool, classification, destination, and roles')
    if any(not isinstance(value[k], str) or len(value[k]) > 200 for k in ('tool', 'classification', 'destination')):
        raise ValueError('tool, classification, and destination must be strings of at most 200 characters')
    if not isinstance(value['roles'], list) or len(value['roles']) > 20 or any(not isinstance(r, str) or len(r) > 100 for r in value['roles']):
        raise ValueError('roles must be an array of up to 20 strings')
    return value


def evaluate(opa_url, value):
    body = json.dumps({'input': value}).encode()
    req = Request(opa_url.rstrip('/') + '/v1/data/toolrisk/decision', data=body, headers={'Content-Type': 'application/json'})
    try:
        with urlopen(req, timeout=2) as response:
            result = json.load(response).get('result')
    except (OSError, ValueError, URLError) as exc:
        raise RuntimeError('Policy service unavailable or invalid response') from exc
    if (not isinstance(result, dict) or type(result.get('allow')) is not bool
            or not isinstance(result.get('reasons'), list)
            or any(not isinstance(reason, str) for reason in result['reasons'])
            or (result['allow'] and result['reasons'])
            or (not result['allow'] and not result['reasons'])):
        raise RuntimeError('Policy service returned an invalid decision')
    return result


def process(value, mode, evaluator):
    validate(value)
    decision = evaluator(value)
    # Unknown tools and classifications never reach a simulated dispatcher, even in dry-run.
    dispatchable = value['tool'] in TOOLS and value['classification'] in CLASSIFICATIONS
    executed = dispatchable and (decision['allow'] or mode == 'dry-run')
    return {'mode': mode, 'policy_decision': 'allow' if decision['allow'] else 'deny',
            'reasons': decision['reasons'], 'simulated_execution': executed,
            'outcome': 'simulated' if executed else 'blocked'}


def make_handler(mode, opa_url):
    class Handler(BaseHTTPRequestHandler):
        def respond(self, status, payload):
            data = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            self.respond(200, {'status': 'ok', 'mode': mode}) if self.path == '/health' else self.respond(404, {'error': 'not found'})

        def do_POST(self):
            if self.path != '/v1/tools/invoke':
                return self.respond(404, {'error': 'not found'})
            try:
                length = int(self.headers.get('Content-Length', '0'))
                if not 0 < length <= MAX_BODY:
                    raise ValueError('Invalid Content-Length')
                value = json.loads(self.rfile.read(length))
                result = process(value, mode, lambda data: evaluate(opa_url, data))
                logging.info('mode=%s tool=%s decision=%s outcome=%s', mode, value['tool'], result['policy_decision'], result['outcome'])
                self.respond(200 if result['outcome'] == 'simulated' else 403, result)
            except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                self.respond(400, {'error': str(exc)})
            except RuntimeError:
                logging.warning('Policy evaluation failed; request blocked')
                self.respond(503, {'error': 'policy evaluation unavailable', 'outcome': 'blocked'})

        def log_message(self, fmt, *args):
            logging.info('%s', fmt % args)
    return Handler


def main():
    mode = os.environ.get('GATEWAY_MODE', 'enforce')
    if mode not in ('dry-run', 'enforce'):
        raise SystemExit('GATEWAY_MODE must be dry-run or enforce')
    logging.basicConfig(level=logging.INFO, format='%(levelname)s %(message)s')
    server = ThreadingHTTPServer(('0.0.0.0', int(os.environ.get('PORT', '8080'))), make_handler(mode, os.environ.get('OPA_URL', 'http://localhost:8181')))
    logging.info('Gateway listening in %s mode', mode)
    server.serve_forever()


if __name__ == '__main__':
    main()
