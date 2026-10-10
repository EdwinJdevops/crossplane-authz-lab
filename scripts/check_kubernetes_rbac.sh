#!/usr/bin/env bash
set -euo pipefail

namespace=cpal-experiment
subject=system:serviceaccount:${namespace}:cpal-collector

check() {
  local expected="$1" verb="$2" resource="$3"
  local actual status=0
  actual="$(kubectl auth can-i "$verb" "$resource" -n "$namespace" --as="$subject")" || status=$?
  if [[ "$actual" != "$expected" ]]; then
    printf 'RBAC mismatch: %s %s expected=%s observed=%s exit=%s\n' "$verb" "$resource" "$expected" "$actual" "$status" >&2
    exit 1
  fi
  if [[ "$expected" == yes && "$status" -ne 0 ]]; then
    printf 'RBAC positive check failed unexpectedly: %s %s exit=%s\n' "$verb" "$resource" "$status" >&2
    exit 1
  fi
  printf 'RBAC verified: %s %s -> %s (exit=%s)\n' "$verb" "$resource" "$actual" "$status"
}

check yes get pods/cpal-target
check yes get serviceaccounts/cpal-target-sa
check no get pods/not-the-target
check no get serviceaccounts/not-the-target
check no list pods
check no watch pods
check no delete pods/cpal-target
check no update serviceaccounts/cpal-target-sa
