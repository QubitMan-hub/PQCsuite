import json
import time

import pytest

from scripts.pilot import record, read, summary


def test_pilot_metrics_do_not_invent_participants_or_double_count_decisions(tmp_path):
    path = tmp_path/'private/pilot.json'
    assert all(p['status'] == 'not_started' for p in summary(read(path))['pilots'])
    for event in ('setup_started', 'first_scan', 'finding_accepted', 'finding_dismissed', 'fix_started', 'fix_completed', 'support_request'):
        record(path, 'pilot-1', event, 'f1')
    report = summary(read(path))['pilots']
    assert report[0]['setup_seconds'] >= 0
    assert report[0]['findings_accepted'] == 0 and report[0]['findings_dismissed'] == 1
    assert len(report[0]['reported_fix_seconds']) == report[0]['support_requests'] == 1
    assert report[0]['verified_endpoint_connections'] == 0
    assert report[1]['setup_seconds'] is None


def test_verified_connection_metrics_reject_stale_failed_and_missing_evidence(tmp_path):
    path, assessment = tmp_path/'pilot.json', tmp_path/'assessment.json'
    with pytest.raises(ValueError, match='Supply'):
        record(path, 'pilot-1', 'connection_verified', 'f1')
    observed = {'finding': 'f1', 'state': 'verified_pq_connection', 'checked': time.time(), 'source_finished': 10,
                'target': 'service:8443', 'release': 'r1', 'certificate_sha256': 'a'*64}
    for change, finished in (({'state': 'not_verified'}, 10), ({'checked': 0}, 10), ({}, 11)):
        assessment.write_text(json.dumps({'finished': finished, 'verifications': [observed | change]}))
        with pytest.raises(ValueError, match='current successful'):
            record(path, 'pilot-1', 'connection_verified', 'f1', assessment)
    assessment.write_text(json.dumps({'finished': 10, 'verifications': [observed]}))
    record(path, 'pilot-1', 'connection_verified', 'f1', assessment)
    record(path, 'pilot-1', 'connection_verified', 'f1', assessment)
    assert summary(read(path))['pilots'][0]['verified_endpoint_connections'] == 1
