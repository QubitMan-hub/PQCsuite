"""Moved to Acxelin Readiness (acxelin_readiness.workspace); endpoint verification waits here for the core's CRL checks (Stage 2)."""
from acxelin_readiness.workspace import *  # noqa: F401,F403
from acxelin_readiness.workspace import ProjectStore, ScanStopped, append_history, finding_id, read_history, sample_project, scan  # noqa: F401


def verify_endpoint(target, ca, expected_sha256, crl=None):
    """Authenticate a strict PQ TLS connection and pin the operator's deployment certificate."""
    from cryptography.hazmat.primitives import hashes
    from . import tls
    from .pki import CAError, verify_crl, now
    from acxelin_readiness.endpoints import endpoint, PQ
    protocol, host, port = endpoint(target)
    if protocol != 'tls':
        raise ValueError('Deployment verification currently supports TLS endpoints only')
    result = {'state': 'not_verified', 'policy': 'strict', 'boundary':
              'One authenticated PQ connection at this time; does not establish all client paths, fallback refusal, application behavior or source provenance'}
    context = None
    try:
        context = tls.client_context(ca=ca, policy_name='strict')
        with tls.connect(host, port, context, timeout=5) as connection:
            certificate = connection.peer_certificate()
            fingerprint = certificate.fingerprint(hashes.SHA256()).hex() if certificate else ''
            result |= {'group': connection.group, 'certificate_sha256': fingerprint}
            if fingerprint != expected_sha256:
                result['error'] = 'Certificate differs from the expected deployment; check the release and certificate rotation'
            elif connection.group not in PQ:
                result['error'] = 'Post-quantum key exchange was not established'
            else:
                if not crl:
                    raise CAError('A current issuer CRL is required')
                revocations = verify_crl(Path(crl).read_bytes(), connection.peer_chain()[1:2])
                if revocations.issuer != certificate.issuer or revocations.last_update_utc > now() or not revocations.next_update_utc or revocations.get_revoked_certificate_by_serial_number(certificate.serial_number):
                    raise CAError('Revocation evidence does not establish a current valid leaf certificate')
                result['state'] = 'verified_pq_connection'
                result['revocation'] = 'Leaf certificate checked against current issuer CRL'
    except (tls.TLSError, CAError, OSError, ValueError):
        result['error'] = 'Verified strict TLS connection failed; check endpoint, CA trust, certificate name/expiry, current issuer CRL and PQ policy'
    finally:
        if context:
            context.close()
    return result
