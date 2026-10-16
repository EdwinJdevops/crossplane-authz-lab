"""Verifier-owned TokenReview client; caller never supplies the review response.

The caller supplies a bearer token to verify; Kubernetes API authenticates it.
The verifier's own API token and pinned cluster CA must be trusted inputs.
"""

import json
import ssl
import urllib.request

from cpal.tokenreview_result import TokenReviewResult, validate_tokenreview


def authenticate_collector(*, api_url: str, cluster_ca: str, verifier_token: str, candidate_token: str, expected_username: str, expected_uid: str, audience: str) -> TokenReviewResult:
    if not api_url.startswith('https://') or not all((cluster_ca, verifier_token, candidate_token, expected_username, expected_uid, audience)):
        return TokenReviewResult(False, None, 'MISSING_TRUST_CONFIGURATION')
    try:
        context = ssl.create_default_context(cafile=cluster_ca)
        body = json.dumps({'apiVersion': 'authentication.k8s.io/v1', 'kind': 'TokenReview', 'spec': {'token': candidate_token, 'audiences': [audience]}}).encode('utf-8')
        request = urllib.request.Request(api_url.rstrip('/') + '/apis/authentication.k8s.io/v1/tokenreviews', data=body, method='POST', headers={'Authorization': 'Bearer ' + verifier_token, 'Content-Type': 'application/json'})
        with urllib.request.build_opener(urllib.request.HTTPSHandler(context=context)).open(request, timeout=10) as response:
            if response.status != 201:
                return TokenReviewResult(False, None, 'TOKENREVIEW_HTTP_ERROR')
            result = json.load(response)
        return validate_tokenreview(result, expected_username=expected_username, expected_uid=expected_uid, expected_audience=audience)
    except (OSError, ValueError, KeyError, TypeError):
        return TokenReviewResult(False, None, 'TOKENREVIEW_UNAVAILABLE')
