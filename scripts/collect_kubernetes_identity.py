"""Read a scoped Pod and ServiceAccount from a configured Kubernetes API.

Use a trusted kubeconfig or in-cluster identity. Never disable TLS checks.
The result is a structural observation, NOT authorization evidence.
"""
import argparse
import json
from dataclasses import asdict

from cpal.kubernetes_consistency import collect_stable_identity


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--namespace', default='cpal-experiment')
    parser.add_argument('--pod', default='cpal-target')
    parser.add_argument('--in-cluster', action='store_true')
    args = parser.parse_args()
    from kubernetes import client, config
    if args.in_cluster:
        config.load_incluster_config()
    else:
        config.load_kube_config()
    observation = collect_stable_identity(client.CoreV1Api(), namespace=args.namespace, pod_name=args.pod)
    print(json.dumps(asdict(observation), indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
