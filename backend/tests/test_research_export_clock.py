"""Deterministic regressions for fractional coverage and integer signed timestamps."""
from datetime import datetime, timezone
from types import SimpleNamespace
import pytest
from app.access import research_bridge as B


def clock(monkeypatch, start, *, rollback=False):
    state={'now':start,'waits':[]}
    def sleep(seconds):
        assert 0 < seconds < 1
        state['waits'].append(seconds)
        state['now'] = start-1 if rollback else state['now']+seconds
    monkeypatch.setattr(B,'time',SimpleNamespace(time=lambda:state['now'],sleep=sleep))
    return state


def test_same_second_microseconds_wait_without_altering_recorded_coverage(monkeypatch):
    state=clock(monkeypatch,1000.25);coverage=datetime.fromtimestamp(1000.125,timezone.utc)
    issued=B._export_second(coverage)
    assert issued==1001 and state['waits']==[.75]
    assert coverage.timestamp()==1000.125 and issued+300==1301


def test_coverage_already_within_whole_second_needs_no_wait(monkeypatch):
    state=clock(monkeypatch,1001.25)
    assert B._export_second(datetime.fromtimestamp(1000.999999,timezone.utc))==1001
    assert state['waits']==[]


def test_genuine_future_coverage_fails_without_wait(monkeypatch):
    state=clock(monkeypatch,1000.25)
    with pytest.raises(ValueError,match='Export clock/coverage differs'):
        B._export_second(datetime.fromtimestamp(1000.5,timezone.utc))
    assert state['waits']==[]


def test_clock_rollback_after_wait_stays_a_hard_failure(monkeypatch):
    state=clock(monkeypatch,1000.25,rollback=True)
    with pytest.raises(ValueError,match='Export clock/coverage differs'):
        B._export_second(datetime.fromtimestamp(1000.125,timezone.utc))
    assert state['waits']==[.75]
