"""Private, local pilot measurements. Labels are pseudonyms; do not record source, tokens or customer names."""
import argparse
import json
import time
from pathlib import Path

from pqcsuite.storage import locked, write

EVENTS = ('setup_started', 'first_scan', 'finding_accepted', 'finding_dismissed', 'fix_started', 'fix_completed', 'support_request', 'connection_verified')


def read(path):
    if not path.exists():
        return []
    with path.open('rb') as stream:
        raw = stream.read(2_000_001)
    if len(raw) > 2_000_000:
        raise ValueError('Pilot record exceeds 2 MB')
    rows = json.loads(raw)
    if not isinstance(rows, list) or len(rows) > 5000:
        raise ValueError('Expected at most 5000 pilot events')
    for row in rows:
        if not isinstance(row, dict) or row.get('event') not in EVENTS or row.get('pilot') not in ('pilot-1', 'pilot-2', 'pilot-3') or type(row.get('at')) not in (int, float) or not 0 <= row['at'] < 2**53:
            raise ValueError('Invalid pilot event')
    return rows


def summary(rows):
    pilots = []
    for pilot in ('pilot-1', 'pilot-2', 'pilot-3'):
        events = sorted((r for r in rows if r['pilot'] == pilot), key=lambda r: r['at'])
        started = next((r['at'] for r in events if r['event'] == 'setup_started'), None)
        ready = next((r['at'] for r in events if r['event'] == 'first_scan' and started is not None and r['at'] >= started), None)
        fixes, decisions, durations = {}, {}, []
        connections = set()
        for row in events:
            finding = row.get('finding', '')
            if row['event'] in ('finding_accepted', 'finding_dismissed'):
                decisions[finding] = row['event']
            elif row['event'] == 'fix_started':
                fixes[finding] = row['at']
            elif row['event'] == 'fix_completed' and finding in fixes:
                durations.append(row['at'] - fixes.pop(finding))
            elif row['event'] == 'connection_verified':
                connections.add((finding, row['target'], row['release']))
        pilots.append({'pilot': pilot, 'status': 'recorded' if events else 'not_started', 'setup_seconds': ready - started if ready is not None else None,
                       'findings_accepted': sum(v == 'finding_accepted' for v in decisions.values()),
                       'findings_dismissed': sum(v == 'finding_dismissed' for v in decisions.values()),
                       'reported_fix_seconds': durations, 'verified_endpoint_connections': len(connections),
                       'support_requests': sum(r['event'] == 'support_request' for r in events)})
    return {'pilots': pilots, 'boundary': 'Setup, decisions and fix completion are operator-recorded. Verified connections are imported observations, not verified source provenance or complete migrations.'}


def record(path, pilot, event, finding='', assessment=None):
    if pilot not in ('pilot-1', 'pilot-2', 'pilot-3') or event not in EVENTS:
        raise ValueError('Choose a supported pilot and event')
    if event.startswith(('finding_', 'fix_')) or event == 'connection_verified':
        if not finding or len(finding) > 120:
            raise ValueError('This event requires a finding identifier of at most 120 characters')
    row = {'pilot': pilot, 'event': event, 'finding': finding, 'at': time.time()}
    if event == 'connection_verified':
        if assessment is None:
            raise ValueError('Supply --assessment with an exported project assessment')
        with Path(assessment).open('rb') as stream:
            raw = stream.read(16_000_001)
        if len(raw) > 16_000_000:
            raise ValueError('Assessment exceeds 16 MB')
        data = json.loads(raw)
        observations = [v for v in data.get('verifications', []) if v.get('finding') == finding]
        latest = max(observations, key=lambda v: v.get('checked', 0), default={})
        if latest.get('state') != 'verified_pq_connection' or latest.get('source_finished') != data.get('finished') or not 0 <= time.time() - latest.get('checked', 0) <= 86400:
            raise ValueError('A current successful endpoint observation is required; reverify after rescans or failed probes')
        row |= {key: latest[key] for key in ('target', 'release', 'certificate_sha256', 'checked')}
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with locked(path.parent, '.' + path.name + '.lock'):
        rows = read(path)
        if len(rows) >= 5000:
            raise ValueError('Pilot record is full; archive it before starting another cohort')
        raw = json.dumps(rows + [row], indent=2).encode()
        if len(raw) > 2_000_000:
            raise ValueError('Pilot record exceeds 2 MB')
        write(path, raw, secret=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--file', type=Path, required=True)
    parser.add_argument('--pilot', choices=['pilot-1', 'pilot-2', 'pilot-3'])
    parser.add_argument('--event', choices=EVENTS)
    parser.add_argument('--finding', default='')
    parser.add_argument('--assessment', type=Path)
    args = parser.parse_args()
    try:
        if args.event:
            if not args.pilot:
                parser.error('--event requires --pilot')
            record(args.file, args.pilot, args.event, args.finding, args.assessment)
        print(json.dumps(summary(read(args.file)), indent=2))
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.error(str(error))


if __name__ == '__main__':
    main()
