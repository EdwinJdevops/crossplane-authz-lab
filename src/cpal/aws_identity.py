"""Verifier-owned STS principal check."""

import re


def valid_expected_identity(account, arn):
    if not isinstance(account, str) or not re.fullmatch(r'[0-9]{12}', account):
        return False
    return isinstance(arn, str) and re.fullmatch(
        r'arn:aws(?:-us-gov|-cn)?:sts::' + account
        + r':assumed-role/[A-Za-z0-9+=,.@_-]{1,64}/[A-Za-z0-9+=,.@_-]{2,64}',
        arn,
    ) is not None


def verify_identity(sts, *, expected_account, expected_arn):
    if not valid_expected_identity(expected_account, expected_arn):
        return False
    response = sts.get_caller_identity()
    if not isinstance(response, dict):
        return False
    user_id = response.get('UserId')
    return (
        response.get('Account') == expected_account
        and response.get('Arn') == expected_arn
        and isinstance(user_id, str)
        and bool(user_id.strip())
    )
