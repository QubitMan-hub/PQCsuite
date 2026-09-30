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


def test_repository_registration_is_scoped_and_idempotent(tmp_path):
    approved=tmp_path/'approved'; approved.mkdir()
    repo=approved/'safe'; repo.mkdir()
    outside=tmp_path/'private'; outside.mkdir()
    (approved/'link').symlink_to(outside, target_is_directory=True)
    app=App(Settings(repository_directory=str(approved), audit_log=str(tmp_path/'audit.jsonl')), token='test')
    for name in ('../private', str(outside), 'link', '.hidden', 'safe/child', 'safe\\child', '', None):
        with pytest.raises(ValueError):
            app.register_project({'name':name})
    assert app.project_status()['available']==['safe']
    assert app.register_project({'name':'safe'})=={'project':0}
    assert app.register_project({'name':'safe'})=={'project':0}
    assert app.project_status()['projects']==[{'id':0,'name':'safe'}]
    assert 'last' not in app.project_status(brief=True)


def test_history_concurrent_writers_and_console_restart(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from pqcsuite.project import read_history
    history=tmp_path/'history.json'
    def record(i):
        append_history(history, {'project':str(i),'finished':i,'summary':{'crypto_assets':i}})
    with ThreadPoolExecutor(max_workers=8) as workers:
        list(workers.map(record,range(40)))
    assert {r['project'] for r in read_history(history)}=={str(i) for i in range(40)}
    app=App(Settings(project_history=str(history)), token='test')
    assert len(app.project_status()['history'])==40


def test_bad_history_does_not_discard_successful_scan(tmp_path):
    fixture(tmp_path)
    history=tmp_path/'history.json'; history.write_text('{')
    result=scan(tmp_path, out=tmp_path/"pqcsuite-out", history=history)
    assert json.loads((tmp_path/"pqcsuite-out/assessment.json").read_text())["notes"] == result["notes"]
    assert result['summary']['resolved_calls']==1
    assert any('History could not be saved' in n for n in result['notes'])
    assert history.read_text()=='{'


def test_history_read_limit_and_private_lock_symlink(tmp_path):
    from pqcsuite.project import read_history
    history=tmp_path/'history.json'; history.write_bytes(b' '*1_000_001)
    with pytest.raises(ValueError, match='1 MB'):
        read_history(history)
    outside=tmp_path/'private'; outside.write_text('UNCHANGED')
    (tmp_path/'.history.json.lock').symlink_to(outside)
    if os.name != 'nt':
        with pytest.raises(OSError):
            append_history(history, {'project':'a','finished':1,'summary':{}})
        assert outside.read_text()=='UNCHANGED'


def test_history_updates_are_preserved_across_processes(tmp_path):
    import subprocess
    import sys
    from pqcsuite.project import read_history
    history=tmp_path/'history.json'
    script='from pqcsuite.project import append_history; import sys; [append_history(sys.argv[1], {"project":sys.argv[2]+"-"+str(i), "finished":i, "summary":{}}) for i in range(20)]'
    children=[subprocess.Popen([sys.executable,'-c',script,str(history),str(i)]) for i in range(3)]
    try:
        assert [child.wait(timeout=30) for child in children]==[0,0,0]
        assert len({r['project'] for r in read_history(history)})==60
    finally:
        for child in children:
            if child.poll() is None:
                child.kill(); child.wait()
