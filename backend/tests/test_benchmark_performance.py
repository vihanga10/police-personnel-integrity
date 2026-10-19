"""The performance benchmark tool: statistics conventions, pacing, and a real run against a disposable packaged copy."""
import importlib.util
import json
from pathlib import Path
import time
import pytest

from unit_totp_fixture import setup  # noqa: F401  (pytest fixture)
from test_persistent_access import configured as totp_configured
from app.access.public_demo_bundle import build

SPEC = importlib.util.spec_from_file_location('benchmark_performance', Path(__file__).resolve().parents[1] / 'scripts/benchmark_performance.py')
B = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(B)
REPO = Path(__file__).resolve().parents[2]


def test_percentile_is_nearest_rank_and_p95_needs_at_least_twenty_samples():
    thirty = list(range(1, 31))
    assert B.percentile(thirty, 95) == 29 and B.percentile(thirty, 50) == 15 and B.percentile(thirty, 100) == 30 and B.percentile([7], 95) == 7
    assert B.percentile(list(range(1, 21)), 95) == 19 and B.percentile(list(reversed(thirty)), 95) == 29
    s = B.summarize([float(x) for x in thirty])
    assert s == {'n': 30, 'min': 1.0, 'median': 15.5, 'p95': 29.0, 'max': 30.0}
    assert B.summarize([1.0, 2.0, 3.0])['p95'] is None and B.summarize([])['n'] == 0 and B.summarize([])['median'] is None
    assert B.summarize([float(x) for x in range(1, 20)])['p95'] is None and B.summarize([float(x) for x in range(1, 21)])['p95'] == 19.0


def test_requests_are_paced_to_the_applications_limits_and_a_429_is_waited_out_not_timed(monkeypatch):
    slept, calls = [], []
    monkeypatch.setattr(B.time, 'sleep', lambda seconds: slept.append(seconds))
    client = B.Client(1, 'host')
    answers = iter([(200, b'', 5.0, None), (200, b'', 6.0, None), (429, b'', 1.0, None), (200, b'', 7.0, None), (200, b'', 8.0, None)])
    client._request = lambda method, path, body=None: calls.append(path) or next(answers)
    assert client.request('GET', '/api/officers/x')[2] == 5.0
    assert client.request('GET', '/api/research/officers/y')[2] == 6.0
    assert any(0.5 < s <= B.Client.PACE['SEARCH'] for s in slept), 'the second lookup waited for the per-minute budget'
    assert client.request('POST', '/api/research/history', {})[2] == 7.0 and client.waits == 1 and any(s > 1 for s in slept), 'a 429 is retried after the window'
    assert client.request('GET', '/api/research/personnel-dashboard')[2] == 8.0
    assert (B.Client.bucket('/api/research/personnel-dashboard'), B.Client.bucket('/api/research/unit-dashboard'), B.Client.bucket('/api/officers/search'),
            B.Client.bucket('/api/research/browse'), B.Client.bucket('/api/auth/session'), B.Client.bucket('/api/auth/login')) == ('DASHBOARD', 'DASHBOARD', 'SEARCH', 'SEARCH', None, None)
    assert B.Client.PACE['SEARCH'] > 1.0 and B.Client.PACE['DASHBOARD'] > 5.0, 'at least the application limit (60 and 12 per minute)'


def test_targets_are_judged_only_on_valid_measurements():
    def entry(p95, failures=0):
        return {'same': {'n': 30, 'p95': p95, 'failures': failures}, 'varied': {'n': 30, 'p95': p95, 'failures': failures}}
    report = {'categories': {'search_by_name': 'search_profile', 'officer_workspace': 'search_profile', 'personnel_dashboard': 'dashboard', 'history_query': 'analysis'},
              'warm': {'search_by_name': entry(900.0), 'officer_workspace': entry(2500.0), 'personnel_dashboard': {'same': {'n': 30, 'p95': 4000.0, 'failures': 0}}, 'history_query': entry(99999.0)},
              'cold': {'personnel_dashboard': {'n': 5, 'max': 40000.0}}}
    t = B.evaluate_targets(report)
    assert t['routine_search_profile_warm_p95_ms']['met'] is True and t['routine_search_profile_warm_p95_ms']['worst_same'] == 2500.0
    assert t['dashboard_warm_p95_ms']['met'] is True and t['dashboard_cold_first_ms']['met'] is True
    report['warm']['officer_workspace'] = entry(3100.0)
    report['warm']['personnel_dashboard']['same']['p95'] = 5100.0
    report['cold']['personnel_dashboard']['max'] = 61000.0
    t = B.evaluate_targets(report)
    assert (t['routine_search_profile_warm_p95_ms']['met'], t['dashboard_warm_p95_ms']['met'], t['dashboard_cold_first_ms']['met']) == (False, False, False)
    report['warm']['personnel_dashboard']['same'] = {'n': 0, 'p95': None, 'failures': 30}
    report['cold']['personnel_dashboard'] = {'n': 0, 'max': None}
    t = B.evaluate_targets(report)
    assert t['dashboard_warm_p95_ms']['met'] is None and t['dashboard_cold_first_ms']['met'] is None, 'no valid timing means not measured, never passed'
    # an operation with failures is excluded from the judgement
    report['warm']['search_by_name'] = entry(10000.0, failures=3)
    assert B.evaluate_targets(report)['routine_search_profile_warm_p95_ms']['worst_same'] == 3100.0


def test_benchmark_runs_end_to_end_on_an_isolated_copy_and_never_records_credentials(setup, monkeypatch, tmp_path):
    d = setup
    totp_configured(d)
    origin = 'https://ppi-bench.example-university.edu:%d' % B.free_port()
    bundle = d['app'].parent / 'bundle'
    build(d['app'], bundle, origin=origin, server_root=str(bundle), server_repo=str(REPO))
    monkeypatch.setattr(B.Client, 'PACE', {'SEARCH': 0.0, 'DASHBOARD': 0.0})
    creds = B.credentials(d['app'] / 'credentials.json', d['app'] / 'totp-enrollment-private.json', 'research.igp')
    work = tmp_path / 'work'
    work.mkdir(mode=0o700)
    report = B.benchmark(bundle, origin, 'research.igp', creds, cold_starts=1, warm_n=2, warmups=0, seed=7, directory=work)
    names = {'search_by_name', 'officer_identity', 'officer_workspace', 'history_query', 'authority_list', 'contradiction_list', 'integrity_view', 'personnel_dashboard', 'unit_dashboard'}
    assert set(report['warm']) == names and set(report['cold']) == names and report['officers_sampled'] == 2 and report['corpus_officers_visible_to_account'] == 2
    for name in names - {'personnel_dashboard', 'unit_dashboard'}:
        assert report['cold'][name]['n'] == 1 and report['cold'][name]['failures'] == 0, name
        assert report['warm'][name]['same']['n'] == 2 and report['warm'][name]['same']['failures'] == 0, name
        assert report['warm'][name]['same']['min'] > 0
    for name in ('search_by_name', 'officer_identity', 'officer_workspace', 'history_query', 'authority_list', 'contradiction_list', 'integrity_view'):
        assert report['warm'][name]['varied']['distinct_officers'] == 2 and report['warm'][name]['varied']['failures'] == 0, name
    assert report['warm']['personnel_dashboard']['same']['failures'] + report['warm']['personnel_dashboard']['same']['n'] == 2 and 'varied' not in report['warm']['personnel_dashboard']
    # no unit account supplied: the unit dashboard is reported as not measured, never as a timing or a pass
    assert report['warm']['unit_dashboard'] == {'not_measured': 'UNIT_ACCOUNT_REQUIRED'} and report['cold']['unit_dashboard']['not_measured'] == 'UNIT_ACCOUNT_REQUIRED'
    assert report['officers_dropped_for_unreadable_workspace'] == 0
    assert len(report['startup_seconds']) == 1 and report['startup_seconds'][0] > 0 and report['rate_limit_waits'] == 0
    text = json.dumps(report)
    for secret in (creds[0], creds[1], 'ppi-session', 'csrf'):
        assert secret not in text
    out = tmp_path / 'result.json'
    report['targets'] = B.evaluate_targets(report)
    out.write_text(json.dumps(report))
    assert json.loads(out.read_text())['targets']['routine_search_profile_warm_p95_ms']['met'] in (True, False, None)


def test_unit_account_is_used_for_the_unit_dashboard_and_refusals_are_recorded_with_their_status(setup, monkeypatch, tmp_path):
    d = setup
    totp_configured(d)
    origin = 'https://ppi-bench.example-university.edu:%d' % B.free_port()
    bundle = d['app'].parent / 'bundle'
    build(d['app'], bundle, origin=origin, server_root=str(bundle), server_repo=str(REPO))
    monkeypatch.setattr(B.Client, 'PACE', {'SEARCH': 0.0, 'DASHBOARD': 0.0})
    paths = (d['app'] / 'credentials.json', d['app'] / 'totp-enrollment-private.json')
    work = tmp_path / 'work'
    work.mkdir(mode=0o700)
    # A unit-scoped SDIG account may open the unit dashboard, so it is timed with that account, not with the national one.
    report = B.benchmark(bundle, origin, 'research.igp', B.credentials(*paths, 'research.igp'), cold_starts=1, warm_n=2, warmups=0, seed=3, directory=work,
                         unit=('research.sdig', B.credentials(*paths, 'research.sdig')), only={'officer_identity', 'unit_dashboard'})
    assert set(report['warm']) == {'officer_identity', 'unit_dashboard'} and report['unit_account'] == 'research.sdig'
    assert report['warm']['unit_dashboard']['same']['n'] == 2 and report['warm']['unit_dashboard']['same']['failures'] == 0 and report['failure_statuses'] == {}
    assert report['cold']['unit_dashboard']['n'] == 1 and report['relogins'] == 0
    # An account that is genuinely refused (a station officer asking for the unit dashboard): refusals are counted with their status, never timed.
    refused = B.benchmark(bundle, origin, 'research.igp', B.credentials(*paths, 'research.igp'), cold_starts=1, warm_n=2, warmups=0, seed=3, directory=work,
                          unit=('research.oic.a', B.credentials(*paths, 'research.oic.a')), only={'unit_dashboard'})
    entry = refused['warm']['unit_dashboard']['same']
    assert entry['n'] == 0 and entry['failures'] == 2 and entry['median'] is None and refused['cold']['unit_dashboard']['n'] == 0 and refused['cold']['unit_dashboard']['failures'] == 1
    assert refused['failure_statuses'] == {'unit_dashboard:403': 3}
