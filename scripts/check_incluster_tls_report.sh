#!/usr/bin/env bash
set -euo pipefail
ns=cpal-experiment
tmp="$(mktemp -d)"
trap 'kubectl -n "$ns" delete job cpal-report-collector --ignore-not-found --wait=false >/dev/null 2>&1 || true; kubectl -n "$ns" delete deployment cpal-verifier --ignore-not-found --wait=false >/dev/null 2>&1 || true; kubectl -n "$ns" delete service cpal-verifier --ignore-not-found >/dev/null 2>&1 || true; kubectl -n "$ns" delete secret cpal-verifier-tls --ignore-not-found >/dev/null 2>&1 || true; kubectl -n "$ns" delete configmap cpal-verifier-code cpal-collector-code cpal-verifier-ca cpal-verifier-runtime --ignore-not-found >/dev/null 2>&1 || true; rm -rf "$tmp"' EXIT
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$tmp/ca.key" -out "$tmp/ca.crt" -days 1 -subj '/CN=CPAL disposable test CA' >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -keyout "$tmp/tls.key" -out "$tmp/tls.csr" -subj '/CN=cpal-verifier.cpal-experiment.svc' >/dev/null 2>&1
printf 'subjectAltName=DNS:cpal-verifier.cpal-experiment.svc,DNS:cpal-verifier.cpal-experiment.svc.cluster.local\nextendedKeyUsage=serverAuth\n' > "$tmp/ext"
openssl x509 -req -in "$tmp/tls.csr" -CA "$tmp/ca.crt" -CAkey "$tmp/ca.key" -CAcreateserial -out "$tmp/tls.crt" -days 1 -extfile "$tmp/ext" >/dev/null 2>&1
kubectl -n "$ns" create secret generic cpal-verifier-tls --from-file=tls.crt="$tmp/tls.crt" --from-file=tls.key="$tmp/tls.key"
kubectl -n "$ns" create configmap cpal-verifier-ca --from-file=ca.crt="$tmp/ca.crt"
uid="$(kubectl -n "$ns" get serviceaccount cpal-collector -o jsonpath='{.metadata.uid}')"
kubectl -n "$ns" create configmap cpal-verifier-runtime --from-literal=collector_uid="$uid"
kubectl -n "$ns" create configmap cpal-verifier-code \
  --from-file=scripts/run_verifier.py \
  --from-file=src/cpal/report_tls.py --from-file=src/cpal/report_http.py \
  --from-file=src/cpal/report_handler.py --from-file=src/cpal/independent_pod_observation.py --from-file=src/cpal/report_protocol.py \
  --from-file=src/cpal/challenge_issuer.py --from-file=src/cpal/challenge_store.py \
  --from-file=src/cpal/challenge_verified_report.py --from-file=src/cpal/tokenreview_client.py \
  --from-file=src/cpal/tokenreview_result.py
kubectl -n "$ns" create configmap cpal-collector-code --from-file=scripts/run_collector.py --from-file=src/cpal/collector_submit.py
kubectl apply -f deploy/kubernetes/verifier-pod-read-rbac.yaml
kubectl apply -f deploy/kubernetes/verifier-report-deployment.yaml
if ! kubectl -n "$ns" rollout status deployment/cpal-verifier --timeout=180s; then
  kubectl -n "$ns" describe pods -l app=cpal-verifier; kubectl -n "$ns" logs deployment/cpal-verifier || true; exit 1
fi
kubectl apply -f deploy/kubernetes/collector-report-job.yaml
if ! kubectl -n "$ns" wait --for=condition=complete job/cpal-report-collector --timeout=180s; then
  kubectl -n "$ns" describe job/cpal-report-collector; kubectl -n "$ns" logs job/cpal-report-collector || true; kubectl -n "$ns" logs deployment/cpal-verifier || true; exit 1
fi
kubectl -n "$ns" logs job/cpal-report-collector | grep -Fx 'Collector report accepted by verifier'
echo 'Independent collector Job submitted live Pod observation over trusted TLS to verifier Deployment'
