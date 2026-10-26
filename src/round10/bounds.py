"""Separate an analytic fixture certificate from unbounded real trajectories."""
import inspect
from pathlib import Path
import numpy as np
from src.round8.common import canonical, sha

TERMS = ('position', 'target', 'attitude', 'interpolation', 'roundoff', 'boresight', 'horizon', 'root')
ASSUMPTIONS = ('continuous_on_closed_cell', 'body_frame_valid', 'horizon_resolved', 'root_resolved')


def identity(function):
    return dict(module=function.__module__, function=function.__qualname__,
                module_raw_sha256=sha(Path(inspect.getfile(function)).read_bytes()),
                function_source_sha256=sha(inspect.getsource(function).encode('utf-8')))


def analytic_certificate():
    # The only certificate authority in this prototype is this exact synthetic
    # constant polynomial. It cannot be attached to any measured trajectory.
    return dict(source='ROUND10_ANALYTIC_CONSTANT_FIXTURE_V1', units='km', frame='BODY',
                scope='ANALYTIC_FIXTURE_ONLY', domain=[0., 1.],
                polynomial=[[-2., 0., 0., 0.]] * 5,
                terms={k: 0. for k in TERMS}, assumptions={k: True for k in ASSUMPTIONS},
                validation='EXACT_CONSTANT_WITH_ZERO_ERROR', label='TESTED_BEHAVIOR')


def validate_certificate(certificate, polynomial, domain, real_data):
    trusted = analytic_certificate()
    if certificate['source'] != trusted['source']:
        raise ValueError('BOUND_SOURCE_UNTRUSTED')
    if certificate['units'] != 'km' or certificate['frame'] != 'BODY':
        raise ValueError('BOUND_UNITS_OR_FRAME')
    if set(certificate['terms']) != set(TERMS):
        raise ValueError('BOUND_TERMS_MISSING')
    if certificate['assumptions'] != trusted['assumptions']:
        raise ValueError('BOUND_ASSUMPTION_INVALID')
    if real_data or certificate['scope'] != 'ANALYTIC_FIXTURE_ONLY':
        raise ValueError('FIXTURE_BOUND_USED_ON_REAL_DATA')
    if certificate != trusted or np.asarray(polynomial).tolist() != trusted['polynomial'] or list(domain) != trusted['domain']:
        raise ValueError('BOUND_INPUT_BINDING')
    return dict(status='VALID_FOR_ANALYTIC_FIXTURE_ONLY', certificate_sha256=sha(canonical(certificate)))


def envelope(polynomial):
    p = np.asarray(polynomial, dtype=float)
    if p.shape != (5, 4) or not np.isfinite(p).all():
        raise ValueError('INVALID_POLYNOMIAL')
    bernstein = np.stack((p[:, 0], p[:, 0] + p[:, 1]/3,
                          p[:, 0] + 2*p[:, 1]/3 + p[:, 2]/3, p.sum(axis=1)), axis=1)
    return bernstein, np.max(bernstein, axis=1)


def decide(polynomial, domain, *, margin_km=.05, tolerance_km=1e-9,
           certificate=None, real_data=True, boresight_known=False, horizon_known=False, roots_known=False):
    bernstein, raw = envelope(polynomial)
    if not np.isfinite(domain).all() or domain[0] >= domain[1]:
        raise ValueError('INVALID_CELL_DOMAIN')
    padded = raw.copy(); padded[:4] += margin_km
    reason = 'KEEP_NO_VERIFIED_CONTINUOUS_BOUND'; kind = 'KEEP'; proof = None
    if certificate is not None:
        proof = validate_certificate(certificate, polynomial, domain, real_data)
        if not boresight_known:
            reason = 'KEEP_BORESIGHT_UNRESOLVED'
        elif not horizon_known:
            reason = 'KEEP_HORIZON_UNRESOLVED'
        elif not roots_known:
            reason = 'KEEP_ROOT_UNRESOLVED'
        elif np.any(padded + sum(certificate['terms'].values()) < -tolerance_km):
            kind, reason = 'CERTIFIED_REJECT', 'ANALYTIC_FIXTURE_STRICT_NEGATIVE_UPPER_BOUND'
        else:
            reason = 'KEEP_BOUNDARY_OR_POSSIBLE'
    return dict(decision=kind, reason=reason, interval_s=list(map(float, domain)),
                raw_bernstein_km=bernstein.tolist(), raw_upper_km=raw.tolist(),
                margin_added_km=[margin_km]*4+[0.], padded_upper_km=padded.tolist(),
                error_upper_bounds={k: certificate['terms'][k] if certificate else None for k in TERMS},
                bound_validation=proof, missing_bound_terms=[] if certificate else list(TERMS),
                real_data=real_data, boresight_known=boresight_known, horizon_known=horizon_known,
                roots_known=roots_known, units='km', frame='BODY_SCREENING_APPROXIMATION' if real_data else 'BODY',
                checker=identity(decide))
