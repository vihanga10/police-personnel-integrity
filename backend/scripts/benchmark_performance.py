"""Operator tool: Chapter 3, Section 3.9.4 performance timing against an ISOLATED read-only copy of the corpus.

It starts the public read-only launcher on a free loopback port from a bundle built by package_public_demo.py, logs in with the
copy's own accounts (password and one-time code, read from the credential files you point it at; never printed or stored), and times
ordinary HTTPS requests. It never touches the live application, the access log, a database or a chain.

Conventions, fixed before any real run (recorded in every result file):
  * time = wall clock from sending the request to receiving the complete body on a keep-alive HTTPS connection, in milliseconds;
  * COLD = the first request of each operation after a fresh server start (K fresh starts, operations in a fixed order, so a later
    operation may benefit from caches an earlier one warmed); WARM = N timed repetitions after W discarded warm-ups on one start;
  * 'same' repeats one identical request; 'varied' uses N distinct officers drawn with a recorded seed;
  * percentile = nearest rank: the value at rank ceil(p/100 * n) of the sorted samples; p95 is reported only when n >= 20;
  * a non-200 answer is counted as a failure and never as a timing; outliers are kept.
  * the application rate-limits officer lookups (60 a minute) and dashboards (12 a minute) per account; the tool WAITS to respect those
    limits, never bypasses them, and the waiting is never part of a timing. A request answered 429 is retried after the window.
"""
import argparse
import hashlib
import http.client
import json
import math
import os
from pathlib import Path
import platform
import random
import socket
import ssl
import statistics
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.access import totp

BACKEND = Path(__file__).resolve().parents[1]
CONVENTION = {'time': 'request sent to complete body received, milliseconds, keep-alive HTTPS', 'cold': 'first request of each operation after a fresh server start',
              'warm': 'timed repetitions after discarded warm-ups on one start', 'percentile': 'nearest rank, ceil(p/100*n), p95 only when n>=20',
              'failures': 'non-200 answers are counted as failures, never as timings', 'outliers': 'retained',
              'rate_limits': 'officer lookups 60/min and dashboards 12/min per account are respected by waiting; waits are not timings'}
TARGETS_MS = {'search_profile_p95': 3000, 'dashboard_warm_p95': 5000, 'dashboard_cold_first': 60000}


def percentile(values, p):
    ordered = sorted(values)
    return ordered[max(1, math.ceil(p / 100 * len(ordered))) - 1]


def summarize(samples):
    if not samples:
        return {'n': 0, 'min': None, 'median': None, 'p95': None, 'max': None}
    return {'n': len(samples), 'min': round(min(samples), 1), 'median': round(statistics.median(samples), 1),
            'p95': round(percentile(samples, 95), 1) if len(samples) >= 20 else None, 'max': round(max(samples), 1)}


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


class Client:
    def __init__(self, port, host_header):
        self.port, self.host = port, host_header
        self.context = ssl.create_default_context()
        self.context.check_hostname = False
        self.context.verify_mode = ssl.CERT_NONE
        self.connection = None
        self.cookie = self.csrf = None
        self.last, self.waits = {}, 0

    def _connect(self):
        self.connection = http.client.HTTPSConnection('127.0.0.1', self.port, context=self.context, timeout=300)

    PACE = {'SEARCH': 1.05, 'DASHBOARD': 5.3}

    @staticmethod
    def bucket(path):
        if path.endswith('-dashboard'):
            return 'DASHBOARD'
        return 'SEARCH' if path.startswith(('/api/officers', '/api/research/')) else None

    def request(self, method, path, body=None):
        """Paced by the application's own limits; a 429 is waited out and retried (counted in `waits`, never timed)."""
        bucket = self.bucket(path)
        for attempt in range(3):
            if bucket:
                gap = self.PACE[bucket] - (time.monotonic() - self.last.get(bucket, -1e9))
                if gap > 0:
                    time.sleep(gap)
                self.last[bucket] = time.monotonic()
            result = self._request(method, path, body)
            if result[0] != 429:
                return result
            self.waits += 1
            time.sleep(62 - time.time() % 60 + 1)
        return result

    def _request(self, method, path, body=None):
        headers = {'Host': self.host}
        if body is not None:
            headers.update({'Content-Type': 'application/json', 'Origin': 'https://' + self.host})
        if self.cookie:
            headers['Cookie'] = self.cookie
        if self.csrf and method == 'POST':
            headers['X-CSRF-Token'] = self.csrf
        data = json.dumps(body).encode() if body is not None else None
        for attempt in (0, 1):
            if self.connection is None:
                self._connect()
            try:
                start = time.perf_counter()
                self.connection.request(method, path, body=data, headers=headers)
                response = self.connection.getresponse()
                content = response.read()
                elapsed = (time.perf_counter() - start) * 1000
                if response.getheader('Connection', '').lower() == 'close':
                    self.connection.close()
                    self.connection = None
                return response.status, content, elapsed, response
            except (http.client.HTTPException, OSError):
                self.connection = None
                if attempt:
                    raise

    def login(self, username, password, seed, last_counter=None):
        """One-time code login. Each code works once, and an earlier run may have used the nearest windows, so the valid windows are tried in order
        (at most three attempts, inside the application's own 5-a-minute limit); if all are spent, wait for the next window."""
        for round_ in (0, 1):
            now = int(time.time()) // 30
            for counter in [c for c in (now - 1, now, now + 1) if last_counter is None or c > last_counter]:
                status, _, _, response = self.request('POST', '/api/auth/login', {'username': username, 'password': password, 'totp_code': totp.code(seed, counter)})
                if status == 200:
                    self.cookie = response.getheader('Set-Cookie').split(';')[0]
                    status, content, _, _ = self.request('GET', '/api/auth/session')
                    self.csrf = json.loads(content)['csrf_token']
                    return counter
                if status != 401:
                    raise RuntimeError('login failed for ' + username + ' (' + str(status) + ')')
            if round_ == 0:
                time.sleep(31 - time.time() % 30)
                last_counter = None
        raise RuntimeError('login failed for ' + username + ' (401)')


class Server:
    """The public read-only launcher on a free loopback port, from a bundle; stopped on exit."""
    def __init__(self, bundle, origin_host, port, directory):
        self.bundle, self.origin_host, self.port, self.directory = Path(bundle), origin_host, port, Path(directory)
        self.process = None
        self.startup_seconds = None

    def __enter__(self):
        cert, key = self.directory / 'bench.crt', self.directory / 'bench.key'
        if not cert.exists():
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2', '-subj', '/CN=bench', '-keyout', str(key), '-out', str(cert)],
                           check=True, capture_output=True)
            cert.chmod(0o600)
            key.chmod(0o600)
        log = (self.directory / 'server.log').open('ab')
        started = time.perf_counter()
        self.process = subprocess.Popen([sys.executable, str(BACKEND / 'scripts/serve_public_demo.py'), '--config', str(self.bundle / 'private/workspace-config.json'),
                                         '--certificate', str(cert), '--tls-key', str(key), '--port', str(self.port), '--accept-public-synthetic-demo'],
                                        cwd=BACKEND, stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
        probe = Client(self.port, self.origin_host)
        deadline = time.monotonic() + 180
        while True:
            if self.process.poll() is not None:
                raise RuntimeError('benchmark server exited during start-up (see server.log in the temporary folder)')
            try:
                probe.request('GET', '/api/auth/session')
                break
            except OSError:
                if time.monotonic() > deadline:
                    raise RuntimeError('benchmark server start-up timed out')
                time.sleep(0.1)
        self.startup_seconds = round(time.perf_counter() - started, 2)
        return self

    def __exit__(self, *exc):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()


def sample_officers(client, count, seed):
    """Seeded distinct officers via the directory browse (one call each, within the rate limit); also the corpus size visible to the account."""
    def browse(offset, limit):
        status, content, _, _ = client.request('POST', '/api/research/browse', {'kind': 'NAME', 'query': '', 'availability': 'ALL', 'level': 'ALL', 'scope_id': '', 'limit': limit, 'offset': offset})
        if status != 200:
            raise RuntimeError('officer sampling failed (' + str(status) + ')')
        return json.loads(content)
    total = browse(0, 1)['total']
    rng = random.Random(seed)
    picked = []
    for offset in rng.sample(range(total), min(count, total)):
        picked += browse(offset, 1)['items'][:1]
    return picked, total


def operations():
    """(name, kind, method, path or builder, body builder, category). 'officer' operations take an officer; others are global."""
    ident = lambda o: o['officer_uid']
    return [
        ('search_by_name', 'officer', 'POST', lambda o: '/api/officers/search', lambda o: {'kind': 'NAME', 'query': (o.get('names') or [''])[0].split(' ')[0][:30] or 'a'}, 'search_profile'),
        ('officer_identity', 'officer', 'GET', lambda o: '/api/officers/' + ident(o), None, 'search_profile'),
        ('officer_workspace', 'officer', 'GET', lambda o: '/api/research/officers/' + ident(o), None, 'search_profile'),
        ('history_query', 'officer', 'POST', lambda o: '/api/research/history', lambda o: {'officer_uid': ident(o), 'effective_on': o['coverage_end'][:10], 'known_at': o['coverage_end']}, 'analysis'),
        ('authority_list', 'officer', 'POST', lambda o: '/api/research/authority', lambda o: {'officer_uid': ident(o), 'known_at': None, 'action_on': None, 'status': 'ALL', 'limit': 25, 'offset': 0}, 'analysis'),
        ('contradiction_list', 'officer', 'POST', lambda o: '/api/research/contradictions', lambda o: {'officer_uid': ident(o), 'effective_on': o['coverage_end'][:10], 'known_at': o['coverage_end'],
            'dimension': 'ALL', 'status': 'ALL', 'relationship': 'ALL', 'limit': 25, 'offset': 0}, 'analysis'),
        ('integrity_view', 'officer', 'GET', lambda o: '/api/research/officers/' + ident(o) + '/integrity', None, 'analysis'),
        ('personnel_dashboard', 'global', 'GET', lambda o: '/api/research/personnel-dashboard', None, 'dashboard'),
        ('unit_dashboard', 'global', 'GET', lambda o: '/api/research/unit-dashboard', None, 'dashboard'),
    ]


def run_operation(client, op, officer):
    name, kind, method, path, body, category = op
    status, content, elapsed, _ = client.request(method, path(officer), body(officer) if body else None)
    return status, elapsed


def attach_coverage(client, officers):
    """Untimed: each sampled officer's own coverage end (queries for a knowledge time use the officer's own recorded boundary, as the UI does)."""
    kept = []
    for officer in officers:
        status, content, _, _ = client.request('GET', '/api/research/officers/' + officer['officer_uid'])
        if status == 200 and json.loads(content).get('coverage_end'):
            kept.append({**officer, 'coverage_end': json.loads(content)['coverage_end']})
    if not kept:
        raise RuntimeError('no sampled officer had a readable workspace')
    return kept, len(officers) - len(kept)


def credentials(credentials_file, enrollment_file, username):
    passwords = json.loads(Path(credentials_file).read_text())
    seeds = {a['username']: a['secret'] for a in json.loads(Path(enrollment_file).read_text())['accounts']}
    return passwords[username], seeds[username]


def evaluate_targets(report):
    """Chapter 3 targets as pass / fail / not measured, using only warm p95 (n >= 20) or the stated cold figure."""
    out = {}
    warm = report['warm']
    def worst(names, key, variant):
        values = [warm[n][variant][key] for n in names if n in warm and warm[n].get(variant, {}).get('failures', 0) == 0 and warm[n].get(variant, {}).get(key) is not None]
        return max(values) if values else None
    routine = worst([n for n, c in report['categories'].items() if c == 'search_profile'], 'p95', 'same')
    routine_varied = worst([n for n, c in report['categories'].items() if c == 'search_profile'], 'p95', 'varied')
    dash_warm = worst([n for n, c in report['categories'].items() if c == 'dashboard'], 'p95', 'same')
    dash_cold = [report['cold'][n]['max'] for n, c in report['categories'].items() if c == 'dashboard' and n in report['cold'] and report['cold'][n]['n']]
    out['routine_search_profile_warm_p95_ms'] = {'target': TARGETS_MS['search_profile_p95'], 'worst_same': routine, 'worst_varied': routine_varied,
        'met': None if routine is None else (routine <= TARGETS_MS['search_profile_p95'] and (routine_varied is None or routine_varied <= TARGETS_MS['search_profile_p95']))}
    out['dashboard_warm_p95_ms'] = {'target': TARGETS_MS['dashboard_warm_p95'], 'worst': dash_warm, 'met': None if dash_warm is None else dash_warm <= TARGETS_MS['dashboard_warm_p95']}
    out['dashboard_cold_first_ms'] = {'target': TARGETS_MS['dashboard_cold_first'], 'worst_observed': max(dash_cold) if dash_cold else None,
        'met': None if not dash_cold else max(dash_cold) <= TARGETS_MS['dashboard_cold_first']}
    return out


def benchmark(bundle, origin, username, creds, *, cold_starts, warm_n, warmups, seed, directory, unit=None, only=None):
    """`unit` = (username, (password, seed)) for the unit dashboard, which only a unit-scoped SDIG account may open."""
    host, port = urlsplit(origin).netloc, int(urlsplit(origin).port)
    report = {'cold': {}, 'warm': {}, 'categories': {}, 'startup_seconds': [], 'rate_limit_waits': 0, 'relogins': 0, 'failure_statuses': {}}
    cold_samples, cold_failures, counters, sample, corpus, ops = {}, {}, {}, None, None, None

    class Session:
        """A logged-in client renewed (untimed) well before the application's fixed 30-minute session expiry."""
        MAX_AGE = 20 * 60

        def __init__(self, server, name, secrets):
            self.server, self.name, self.secrets, self.waits_before = server, name, secrets, 0
            self._login()

        def _login(self):
            if getattr(self, 'client', None) is not None:
                self.waits_before += self.client.waits
            self.client = Client(self.server.port, host)
            counters[self.name] = self.client.login(self.name, *self.secrets, counters.get(self.name))
            self.created = time.monotonic()

        def current(self):
            if time.monotonic() - self.created > self.MAX_AGE:
                report['relogins'] += 1
                self._login()
            return self.client

        @property
        def waits(self):
            return self.waits_before + self.client.waits

    def clients(server):
        return Session(server, username, creds), (Session(server, unit[0], unit[1]) if unit else None)

    def run(op, officer, main, unit_client):
        if op[0] == 'unit_dashboard':
            if unit_client is None:
                return None, None
            status, elapsed = run_operation(unit_client.current(), op, officer)
        else:
            status, elapsed = run_operation(main.current(), op, officer)
        if status != 200:
            key = op[0] + ':' + str(status)
            report['failure_statuses'][key] = report['failure_statuses'].get(key, 0) + 1
        return status, elapsed

    for start in range(cold_starts):
        with Server(bundle, host, port, directory) as server:
            report['startup_seconds'].append(server.startup_seconds)
            main, unit_client = clients(server)
            if sample is None:
                picked, corpus = sample_officers(main.current(), warm_n, seed)
                sample, report['officers_dropped_for_unreadable_workspace'] = attach_coverage(main.current(), picked)
                ops = [o for o in operations() if only is None or o[0] in only]
            for op in ops:
                report['categories'][op[0]] = op[5]
                status, elapsed = run(op, sample[start % len(sample)], main, unit_client)
                if status is None:
                    continue
                if status == 200:
                    cold_samples.setdefault(op[0], []).append(elapsed)
                else:
                    cold_failures[op[0]] = cold_failures.get(op[0], 0) + 1
            report['rate_limit_waits'] += main.waits + (unit_client.waits if unit_client else 0)
    for name in report['categories']:
        report['cold'][name] = {**summarize(cold_samples.get(name, [])), 'failures': cold_failures.get(name, 0)}
        if name == 'unit_dashboard' and unit is None:
            report['cold'][name]['not_measured'] = 'UNIT_ACCOUNT_REQUIRED'
    with Server(bundle, host, port, directory) as server:
        main, unit_client = clients(server)
        for op in ops:
            name, kind = op[0], op[1]
            if name == 'unit_dashboard' and unit_client is None:
                report['warm'][name] = {'not_measured': 'UNIT_ACCOUNT_REQUIRED'}
                continue
            plans = [('same', [sample[0]] * warm_n)] + ([('varied', (sample * (warm_n // max(1, len(sample)) + 1))[:warm_n])] if kind == 'officer' else [])
            entry = {}
            for variant, officers in plans:
                for _ in range(warmups):
                    run(op, officers[0], main, unit_client)
                timings, failed = [], 0
                for officer in officers:
                    status, elapsed = run(op, officer, main, unit_client)
                    if status == 200:
                        timings.append(elapsed)
                    else:
                        failed += 1
                entry[variant] = {**summarize(timings), 'failures': failed, 'distinct_officers': len({o['officer_uid'] for o in officers})}
            report['warm'][name] = entry
        report['rate_limit_waits'] += main.waits + (unit_client.waits if unit_client else 0)
    return {'convention': CONVENTION, 'corpus_officers_visible_to_account': corpus, 'officers_sampled': len(sample), 'seed': seed, 'cold_starts': cold_starts,
            'warm_repetitions': warm_n, 'warmups_discarded': warmups, 'account': username, 'unit_account': unit[0] if unit else None, **report}


def environment(repo):
    revision = subprocess.run(['git', '-C', str(repo), 'rev-parse', 'HEAD'], capture_output=True, text=True).stdout.strip()
    cpu = subprocess.run(['sysctl', '-n', 'machdep.cpu.brand_string'], capture_output=True, text=True).stdout.strip() or platform.processor()
    memory = subprocess.run(['sysctl', '-n', 'hw.memsize'], capture_output=True, text=True).stdout.strip()
    return {'platform': platform.platform(), 'cpu': cpu, 'logical_cpus': os.cpu_count(), 'memory_gb': round(int(memory) / 2**30, 1) if memory.isdigit() else None,
            'python': platform.python_version(), 'revision': revision, 'mode': 'ISOLATED_READ_ONLY_COPY_NO_UPLOAD_WORKERS_NO_CHAIN',
            'note': 'Upload-intake workers and the officer page\'s uploaded-records lookup are not part of the read-only copy.'}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bundle', type=Path, required=True)
    p.add_argument('--origin', required=True, help='the origin the bundle was built for, with an explicit port, e.g. https://ppi-bench.example-university.edu:9443')
    p.add_argument('--credentials-file', type=Path, required=True)
    p.add_argument('--enrollment-file', type=Path, required=True)
    p.add_argument('--username', default='research.igp')
    p.add_argument('--unit-username', default=None, help='a unit-scoped SDIG account (e.g. research.sdig) so the unit dashboard can be timed')
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--cold-starts', type=int, default=5)
    p.add_argument('--repetitions', type=int, default=30)
    p.add_argument('--warmups', type=int, default=3)
    p.add_argument('--seed', type=int, default=20261019)
    p.add_argument('--only', default=None, help='comma-separated operation names (default: all)')
    a = p.parse_args()
    if not urlsplit(a.origin).port:
        raise SystemExit('The origin must carry the explicit port the bundle was built for.')
    creds = credentials(a.credentials_file, a.enrollment_file, a.username)
    unit = (a.unit_username, credentials(a.credentials_file, a.enrollment_file, a.unit_username)) if a.unit_username else None
    with tempfile.TemporaryDirectory(prefix='ppi-bench-') as directory:
        directory = os.path.realpath(directory)   # the app refuses symlinked private paths (macOS /var is a symlink)
        os.chmod(directory, 0o700)
        report = benchmark(a.bundle, a.origin, a.username, creds, cold_starts=a.cold_starts, warm_n=a.repetitions, warmups=a.warmups, seed=a.seed, directory=directory, unit=unit, only=set(a.only.split(',')) if a.only else None)
    report['environment'] = environment(BACKEND.parent)
    report['targets'] = evaluate_targets(report)
    a.out.write_text(json.dumps(report, indent=1, sort_keys=True))
    print(json.dumps({'written': str(a.out), 'operations': len(report['warm']), 'targets': report['targets']}, indent=1))


if __name__ == '__main__':
    main()
