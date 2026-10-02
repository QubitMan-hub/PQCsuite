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


def test_workspace_rescan_tracking_missing_reappearing_and_privacy(tmp_path):
    from pqcsuite.project import ProjectStore
    repo = tmp_path/'repo'; repo.mkdir(); fixture(repo)
    store = ProjectStore(tmp_path/'private'/'workspace.json')
    first = store.save(repo, scan(repo))
    assert not first['comparison']['baseline']
    finding = first['assets'][0]['id']
    store.track(repo, {'finding': finding, 'owner':'Payments', 'status':'in_progress', 'due':'2099-01-01'})
    (repo/'keys.py').write_text('\n\n'+(repo/'keys.py').read_text())
    second = store.save(repo, scan(repo))
    assert second['assets'][0]['id'] == finding
    assert second['assets'][0]['tracking']['owner'] == 'Payments'
    assert second['comparison']['new'] == 0
    (repo/'keys.py').write_text('def make(): return None\n')
    third = store.save(repo, scan(repo))
    assert third['comparison']['not_observed'] > 0
    assert any(a['id'] == finding for a in third['not_observed'])
    fixture(repo)
    fourth = store.save(repo, scan(repo))
    assert fourth['assets'][0]['tracking']['owner'] == 'Payments'
    assert not fourth['not_observed']
    assert len(ProjectStore(store.path).assessment(repo)['history']) == 4
    assert 'PRIVATE_SENTINEL' not in store.path.read_text()
    if os.name != 'nt':
        assert store.path.stat().st_mode & 0o777 == 0o600


def test_workspace_registration_restart_and_scope_change(tmp_path):
    approved = tmp_path/'approved'; approved.mkdir()
    repo = approved/'safe'; repo.mkdir(); fixture(repo)
    settings = Settings(repository_directory=str(approved), project_state=str(tmp_path/'state.json'), audit_log=str(tmp_path/'audit.jsonl'))
    app = App(settings); app.register_project({'name':'safe'})
    app.project_store.save(repo, scan(repo))
    restarted = App(settings)
    assert restarted.projects == [repo]
    assert restarted.project_status()['last']['assets']
    other = tmp_path/'other'; other.mkdir()
    settings.repository_directory = str(other)
    assert App(settings).projects == []
    settings.repository_directory = str(approved)
    repo.rename(approved/'moved')
    repo.symlink_to(other, target_is_directory=True)
    assert App(settings).projects == []
    with pytest.raises(ValueError):
        restarted.start_project({'project':0})


def test_workspace_invalid_updates_limits_and_competing_writers(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from pqcsuite.project import ProjectStore
    fixture(tmp_path)
    store = ProjectStore(tmp_path/'workspace.json')
    assessment = store.save(tmp_path, scan(tmp_path))
    finding = assessment['assets'][0]['id']
    valid = {'finding':finding, 'owner':'team', 'status':'exception', 'until':'2099-01-01', 'reason':'review'}
    for bad in ({'status':'fixed'}, {'until':'2000-01-01'}, {'reason':''}, {'finding':[]}, {'finding':'unknown'}, {'due':'not-a-date'}, {'owner':'x'*121}):
        with pytest.raises(ValueError):
            store.track(tmp_path, valid | bad)
    with ThreadPoolExecutor(max_workers=8) as workers:
        list(workers.map(lambda i: store.register(tmp_path, str(i)), range(30)))
    assert len(store.read()['registrations'][store.key(tmp_path)]) == 30
    store.track(tmp_path, valid)
    before = store.path.read_bytes()
    store.LIMIT = 1
    with pytest.raises(ValueError):
        store.register(tmp_path, 'refuse')
    assert store.path.read_bytes() == before
    store.LIMIT = 16_000_000
    store.path.write_text('{')
    with pytest.raises(ValueError):
        store.register(tmp_path, 'refuse')
    assert store.path.read_text() == '{'


def test_cancel_and_budget_never_replace_completed_outputs(tmp_path):
    import threading
    from pqcsuite.project import ScanStopped
    fixture(tmp_path)
    out = tmp_path/'pqcsuite-out'
    scan(tmp_path, out=out)
    before = (out/'assessment.json').read_bytes()
    cancelled = threading.Event(); cancelled.set()
    for options in ({'cancel':cancelled}, {'max_files':1}, {'max_bytes':1}, {'timeout':-1}):
        with pytest.raises(ScanStopped):
            scan(tmp_path, out=out, **options)
        assert (out/'assessment.json').read_bytes() == before


def test_sample_project_preserves_edits_and_refuses_symlinks(tmp_path):
    from pqcsuite.project import sample_project
    root = sample_project(tmp_path)
    assert scan(root)['summary']['resolved_calls'] == 1
    (root/'keys.py').write_text('customer edit')
    assert sample_project(tmp_path) == root
    assert (root/'keys.py').read_text() == 'customer edit'
    root.rename(tmp_path/'moved')
    root.symlink_to(tmp_path/'moved', target_is_directory=True)
    with pytest.raises(ValueError):
        sample_project(tmp_path)



def test_console_cancellation_keeps_previous_assessment(tmp_path):
    import threading
    from pqcsuite.project import ScanStopped
    app = App(Settings(project_roots=[str(tmp_path)], audit_log=str(tmp_path/'audit.jsonl')))
    previous = {'project':'completed'}
    app.project_scan['last'] = previous
    entered = threading.Event()
    def pending(*args, **kwargs):
        entered.set()
        assert kwargs['cancel'].wait(5)
        raise ScanStopped('Scan cancelled; the previous completed assessment is preserved')
    with patch('pqcsuite.project.scan', side_effect=pending):
        app.start_project({'project':0})
        assert entered.wait(5)
        assert app.cancel_project() == {'requested':True}
        deadline = time.monotonic() + 5
        while app.project_scan['running'] and time.monotonic() < deadline:
            time.sleep(.01)
    assert not app.project_scan['running']
    assert app.project_scan['last'] is previous
    assert 'cancelled' in app.project_scan['error']
    with pytest.raises(ValueError):
        app.cancel_project()


@pytest.mark.parametrize("directory", ["test_vectors", "lib/Crypto/SelfTest"])
def test_crypto_test_vectors_remain_visible_without_production_migration_candidates(tmp_path, directory):
    root = tmp_path / directory
    root.mkdir(parents=True)
    fixture(root)
    result = scan(tmp_path)
    assert result['assets']
    assert all(a['test_only'] for a in result['assets'])
    assert result['summary']['migration_candidates'] == 0
    # The same algorithm used in production must remain a migration candidate.
    fixture(tmp_path)
    mixed = scan(tmp_path)
    assert mixed['summary']['migration_candidates'] > 0
    assert any(not a['test_only'] for a in mixed['assets'])


def test_deployment_association_is_scoped_and_observation_survives_restart(tmp_path):
    from pqcsuite.pki import CA
    repo = tmp_path/'repo'; repo.mkdir(); fixture(repo)
    CA.init(tmp_path/'pki', 'Root')
    settings = Settings(project_roots=[str(repo)], project_state=str(tmp_path/'state.json'), ca=str(tmp_path/'pki'),
                        scan_targets=['localhost:8443'], audit_log=str(tmp_path/'audit.jsonl'))
    app = App(settings, token='test')
    assessment = scan(repo); assessment['project_key'] = app.project_store.key(repo)
    saved = app.project_store.save(repo, assessment)
    body = {'project': 0, 'finding': saved['assets'][0]['id'], 'target': 'localhost:8443', 'release': 'release-1',
            'association': 'Service deployment manifest maps this source module to this endpoint', 'expected_sha256': 'a'*64}
    with patch('pqcsuite.project.verify_endpoint', return_value={'state': 'verified_pq_connection'}) as probe:
        for changed in ({'target': '169.254.169.254:80'}, {'finding': 'missing'}, {'expected_sha256': 'invalid'}, {'association': ''}):
            status, _ = app.handle('POST', '/api/projects/verify', body | changed)
            assert status == 400
        probe.assert_not_called()
        status, result = app.handle('POST', '/api/projects/verify', body)
        assert status == 200
        assert result['verifications'][0]['source_state'] == 'observed'
    (repo/'keys.py').write_text('def make(): return None\n')
    after = scan(repo); after['project_key'] = app.project_store.key(repo)
    result = app.project_store.save(repo, after)
    observation = result['verifications'][0]
    assert observation['source_state'] == 'not_observed' and observation['rescan_required']
    assert 'not independently verified' in observation['mapping_basis']
    restarted = App(settings, token='test')
    assert restarted.project_status()['last']['verifications'] == result['verifications']
    with pytest.raises(ValueError, match='Assessment changed'):
        app.project_store.record_verification(repo, body, {'state': 'verified_pq_connection'}, assessment['finished'])


def test_persisted_graph_compression_is_lossless_bounded_and_backward_compatible(tmp_path, monkeypatch):
    import base64
    import zlib
    from pqcsuite.project import ProjectStore
    fixture(tmp_path)
    store = ProjectStore(tmp_path/'state.json')
    original = scan(tmp_path)
    saved = store.save(tmp_path, original)
    assert saved['relationships'] == original['relationships']
    record = store.read()['projects'][store.key(tmp_path)]
    assert 'relationships' not in record['assessment'] and 'graph_zlib' in record
    legacy = dict(record, assessment=dict(record['assessment'], relationships=original['relationships']))
    del legacy['graph_zlib']
    assert store.view(legacy)['relationships'] == original['relationships']
    monkeypatch.setattr(ProjectStore, 'GRAPH_LIMIT', 100)
    for packed in ('bad!', base64.b64encode(zlib.compress(b' '*101)).decode(), base64.b64encode(zlib.compress(b'{}') + b'extra').decode()):
        with pytest.raises(ValueError, match='damaged or exceeds'):
            store.view(record | {'graph_zlib': packed})


def test_workspace_upgrades_legacy_version_and_refuses_unknown_version(tmp_path):
    from pqcsuite.project import ProjectStore
    path = tmp_path / 'workspace.json'
    path.write_text(json.dumps({'version': 1, 'registrations': {}, 'projects': {}}))
    store = ProjectStore(path)
    assert store.read()['version'] == 1
    store.register(tmp_path, 'repo')
    assert store.read()['version'] == 2
    path.write_text(json.dumps({'version': 3, 'registrations': {}, 'projects': {}}))
    with pytest.raises(ValueError, match='Invalid project workspace'):
        store.read()
