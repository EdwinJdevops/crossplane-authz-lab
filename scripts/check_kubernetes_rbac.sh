#!/usr/bin/env bash
set -euo pipefail

namespace=cpal-experiment
subject=system:serviceaccount:${namespace}:cpal-collector

check() {
  local expected="$1" verb="$2" resource="$3"
  local actual
  actual="$(kubectl auth can-i "$verb" "$resource" -n "$namespace" --as="$subject")"
  if [[ "$actual" != "$expected" ]]; then
    printf 'RBAC mismatch: %s %s expected=%s observed=%s\n' "$verb" "$resource" "$expected" "$actual" >&2
    exit 1
  fi
  printf 'RBAC verified: %s %s -> %s\n' "$verb" "$resource" "$actual"
}

check yes get pods/cpal-target
check yes get serviceaccounts/cpal-target-sa
check no get pods/not-the-target
check no get serviceaccounts/not-the-target
check no list pods
check no watch pods
check no delete pods/cpal-target
check no update serviceaccounts/cpal-target-sa
