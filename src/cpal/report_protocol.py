"""Strict report ingress parsing. No authentication claims are accepted from JSON.

The verifier must receive the bearer token in a protected transport header,
perform TokenReview itself, and use its own challenge store.
"""

import base64
import binascii
import json

MAX_REQUEST_BYTES = 131072
MAX_REPORT_BYTES = 65536
ALLOWED_KEYS = frozenset({'report_b64', 'envelope'})
ENVELOPE_KEYS = frozenset({'principal', 'nonce', 'execution_id', 'report_sha256'})


class InvalidSubmission(ValueError):
    pass


def parse_submission(body: bytes) -> tuple[bytes, dict]:
    if not isinstance(body, bytes) or len(body) > MAX_REQUEST_BYTES:
        raise InvalidSubmission('INVALID_REQUEST_SIZE')
    try:
        obj = json.loads(body)
    except (UnicodeDecodeError, ValueError) as exc:
        raise InvalidSubmission('INVALID_JSON') from exc
    if not isinstance(obj, dict) or set(obj) != ALLOWED_KEYS:
        raise InvalidSubmission('INVALID_REQUEST_FIELDS')
    envelope = obj['envelope']
    if not isinstance(envelope, dict) or set(envelope) != ENVELOPE_KEYS:
        raise InvalidSubmission('INVALID_ENVELOPE_FIELDS')
    if any(not isinstance(v, str) or not v or len(v) > 512 for v in envelope.values()):
        raise InvalidSubmission('INVALID_ENVELOPE_VALUES')
    encoded = obj['report_b64']
    if not isinstance(encoded, str) or len(encoded) > (MAX_REPORT_BYTES * 4 // 3 + 8):
        raise InvalidSubmission('INVALID_REPORT_ENCODING')
    try:
        report = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise InvalidSubmission('INVALID_REPORT_ENCODING') from exc
    if len(report) > MAX_REPORT_BYTES:
        raise InvalidSubmission('REPORT_TOO_LARGE')
    return report, envelope
