"""Unified scans keep evidence private and preserve optional capability boundaries."""
import json
import os
import time
from unittest.mock import patch

import pytest

from pqcsuite.project import scan, append_history
from pqcsuite.console import App, Settings


def fixture(root):
    (root / 'keys.py').write_text('from cryptography.hazmat.primitives.asymmetric import rsa\ndef make():\n return rsa.generate_private_key(public_exponent=65537, key_size=2048)\n')
    (root / 'api.py').write_text('from keys import make\ndef payment():\n return make()\n# PRIVATE_SENTINEL\n')


def test_scan_exports_and_history_have_evidence_without_source(tmp_path):
    fixture(tmp_path)
    stages = []
    out = tmp_path / 'pqcsuite-out'
    history = tmp_path / 'history.json'
    result = scan(tmp_path, out, history, stages.append)
    assert stages[-1] == 'Complete'
    assert result['summary']['resolved_calls'] == 1
    assert any(a['impact'] and 'api.py#payment' in a['impact']['callers'] for a in result['assets'])
    for f in out.iterdir():
        assert 'PRIVATE_SENTINEL' not in f.read_text()
        if os.name != 'nt':
            assert f.stat().st_mode & 0o777 == 0o600
    rows = json.loads(history.read_text())
    assert set(rows[0]) == {'project', 'finished', 'summary'}
    for _ in range(102):
        append_history(history, result)
    assert len(json.loads(history.read_text())) == 100


def test_registered_project_api_rejects_paths_and_runs_real_scan(tmp_path):
    fixture(tmp_path)
    app = App(Settings(project_roots=[str(tmp_path)], audit_log=str(tmp_path/'audit.jsonl')), token='test')
    for invalid in ('/etc', True, -1, 1, None):
        with pytest.raises(ValueError):
            app.start_project({'project': invalid})
    assert app.start_project({'project':0}) == {'started':0}
    deadline = time.monotonic()+10
    while app.project_status()['running'] and time.monotonic()<deadline:
        time.sleep(.01)
    assert app.project_status()['last']['summary']['resolved_calls'] == 1
    assert app.project_status()['error'] is None


def test_failure_is_retryable_without_source_in_api_error(tmp_path):
    app = App(Settings(project_roots=[str(tmp_path)], audit_log=str(tmp_path/'audit.jsonl')), token='test')
    with patch('pqcsuite.project.scan', side_effect=ValueError('PRIVATE_SENTINEL')):
        app.start_project({'project':0})
        deadline = time.monotonic()+5
        while app.project_status()['running'] and time.monotonic()<deadline:
            time.sleep(.01)
    assert 'PRIVATE_SENTINEL' not in app.project_status()['error']
    assert not app.project_status()['running']
