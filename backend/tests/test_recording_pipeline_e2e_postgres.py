"""Ten real PostgreSQL pipeline scenarios; only the attested disposable launcher."""
import os
import pytest
from scripts import run_isolated_recording_postgres as L
from test_controlled_recording_hook_postgres import staged_postgres
from test_committed_evidence_postgres import postgres_case
from test_recording_tip_witness import witnessed
from test_observed_recording_journal import setup
from test_protected_recording_review import verified, keys
from test_protected_bitemporal_runner import output
from test_witness_secure_transport import secured
from test_recording_pipeline_e2e import CHECKS, IDS, execute

pytestmark=pytest.mark.skipif(not os.environ.get(L.ENV),reason='Run isolated PostgreSQL launcher --suite pipeline-e2e; no database selected.')


@pytest.mark.parametrize('check',CHECKS,ids=IDS)
def test_postgresql_recording_pipeline(staged_postgres,output,monkeypatch,secured,check):
    execute(check,staged_postgres,output,monkeypatch,secured)
