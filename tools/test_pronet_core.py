"""Real VLESS/SOCKS transfers: shared identity, two inbounds, separate counters.

Usage: python3 tools/test_pronet_core.py /absolute/path/to/custom-xray
Only loopback sockets and temporary files are used.
"""
import base64
import functools
import http.server
import json
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid


def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def wait_port(number):
    for _ in range(100):
        try:
            with socket.create_connection(('127.0.0.1', number), .1):
                return
        except OSError:
            time.sleep(.05)
    raise RuntimeError(f'Loopback port {number} did not become ready')


def main():
    binary = str(pathlib.Path(sys.argv[1]).resolve())
    processes = []
    with tempfile.TemporaryDirectory(prefix='pronet-core-test-') as directory:
        root = pathlib.Path(directory)
        payload = b'ProNet detailed accounting\n' * 8192
        (root / 'payload').write_bytes(payload)
        handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=directory)
        web = http.server.ThreadingHTTPServer(('127.0.0.1', 0), handler)
        threading.Thread(target=web.serve_forever, daemon=True).start()

        def start(name, config, ready):
            path = root / (name + '.json')
            path.write_text(json.dumps(config))
            log = (root / (name + '.log')).open('w')
            p = subprocess.Popen([binary, 'run', '-c', str(path)], stdout=log, stderr=log)
            log.close()
            processes.append(p)
            try:
                wait_port(ready)
            except Exception:
                print((root / (name + '.log')).read_text(), file=sys.stderr)
                raise

        alice, bob = str(uuid.uuid4()), str(uuid.uuid4())
        api, a, b = port(), port(), port()
        users = [{'id': alice, 'email': 'alice', 'level': 0}, {'id': bob, 'email': 'bob', 'level': 0}]
        try:
            start('server', {
                'log': {'loglevel': 'warning'}, 'stats': {},
                'api': {'tag': 'api', 'services': ['StatsService']},
                'policy': {'levels': {'0': {'statsUserUplink': True, 'statsUserDownlink': True}}},
                'inbounds': [
                    {'tag': tag, 'listen': '127.0.0.1', 'port': p, 'protocol': 'vless',
                     'settings': {'clients': users, 'decryption': 'none'}} for tag, p in [('a', a), ('b', b)]
                ] + [{'tag': 'api-in', 'listen': '127.0.0.1', 'port': api, 'protocol': 'dokodemo-door',
                      'settings': {'address': '127.0.0.1'}}],
                'outbounds': [{'tag': 'direct', 'protocol': 'freedom'}],
                'routing': {'rules': [{'type': 'field', 'inboundTag': ['api-in'], 'outboundTag': 'api'}]},
            }, api)
            for index, (identity, destination) in enumerate([(alice, a), (alice, b), (bob, a)]):
                socks = port()
                start(f'client-{index}', {
                    'log': {'loglevel': 'warning'},
                    'inbounds': [{'listen': '127.0.0.1', 'port': socks, 'protocol': 'socks',
                                  'settings': {'auth': 'noauth'}}],
                    'outbounds': [{'protocol': 'vless', 'settings': {'vnext': [{
                        'address': '127.0.0.1', 'port': destination,
                        'users': [{'id': identity, 'encryption': 'none'}]}]}}],
                }, socks)
                response = subprocess.check_output(['curl', '-fsS', '--max-time', '10', '--noproxy', '',
                    '--socks5-hostname', f'127.0.0.1:{socks}', f'http://127.0.0.1:{web.server_port}/payload'])
                assert response == payload, 'Transferred data differs'
            time.sleep(.2)
            response = subprocess.check_output([binary, 'api', 'statsquery', f'--server=127.0.0.1:{api}'])
            stats = {r['name']: int(r.get('value', 0)) for r in json.loads(response)['stat']}
            assert stats['pronet>>>capability>>>1'] == 1
            enc = lambda s: base64.urlsafe_b64encode(s.encode()).decode().rstrip('=')
            for email, tags in [('alice', ['a', 'b']), ('bob', ['a'])]:
                for direction in ('uplink', 'downlink'):
                    values = [stats[f'pronet>>>{enc(tag)}>>>{enc(email)}>>>traffic>>>{direction}'] for tag in tags]
                    assert all(n > 0 for n in values)
                    assert sum(values) == stats[f'user>>>{email}>>>traffic>>>{direction}']
            assert not any(f'pronet>>>{enc("b")}>>>{enc("bob")}>>>' in key for key in stats)
            print('PASS: real transfers preserve identity and separate each user/inbound without duplicate totals')
        finally:
            web.shutdown()
            for p in processes:
                p.terminate()
            for p in processes:
                try:
                    p.wait(5)
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait()


if __name__ == '__main__':
    main()
