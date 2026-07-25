# Kubernetes deployment

Kustomize manifests for running the whole platform on a local cluster, with
`NetworkPolicy` objects that actually enforce the isolation model described
in the top-level README: challenge pods cannot reach the platform database,
the platform API, or each other — only DNS.

## Layout

```
deploy/k8s/
├── kind-config.yaml       # local kind cluster, default CNI disabled
├── base/                  # namespace, db, platform-api, frontend, challenges, NetworkPolicies
└── overlays/local/        # thin pass-through — see its kustomization.yaml
```

## Prerequisites

- `kind` and `kubectl` (`brew install kind kubectl`)
- **A CNI that enforces NetworkPolicy.** kind's default CNI (kindnetd) does
  **not** enforce NetworkPolicy — every policy in `base/networkpolicies.yaml`
  would silently be a no-op. `kind-config.yaml` disables the default CNI so
  you can install one that does (this repo was verified against
  [Calico](https://docs.tigera.io/calico/latest/getting-started/kubernetes/kind)).

## Local workflow

```bash
kind create cluster --name ctf-demo --config deploy/k8s/kind-config.yaml

kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.28.0/manifests/calico.yaml
kubectl wait --for=condition=Ready pods --all -n kube-system --timeout=180s

# Build every image with the :local tag the base manifests reference
docker build -t ctf/platform:local ./platform
docker build -t ctf/frontend:local ./frontend
for d in a01-broken-access-control a02-crypto-failures a03-injection \
         a04-insecure-design a05-security-misconfig a06-vulnerable-components \
         a07-auth-failures a08-integrity-failures a09-logging-failures a10-ssrf; do
  docker build -t ctf/$d:local ./challenges/$d
done

kind load docker-image --name ctf-demo \
  ctf/platform:local ctf/frontend:local \
  ctf/a01-broken-access-control:local ctf/a02-crypto-failures:local ctf/a03-injection:local \
  ctf/a04-insecure-design:local ctf/a05-security-misconfig:local ctf/a06-vulnerable-components:local \
  ctf/a07-auth-failures:local ctf/a08-integrity-failures:local ctf/a09-logging-failures:local ctf/a10-ssrf:local

kubectl apply -k deploy/k8s/overlays/local
kubectl wait --for=condition=Ready pod --all -n ctf-demo --timeout=120s

# Seed the challenge catalog + demo account
kubectl exec -n ctf-demo deploy/platform-api -- /app/seed
```

`make k8s-up` / `make k8s-down` wrap the `kubectl apply -k` / `kubectl delete -k`
step (they assume the cluster, images, and CNI are already in place).

## Accessing services

Every Service is `ClusterIP` — reach them with `kubectl port-forward`, which
is injected directly into the pod's network namespace by the kubelet and so
is **not** subject to NetworkPolicy enforcement, unlike normal pod-to-pod or
Service traffic:

```bash
kubectl port-forward -n ctf-demo svc/frontend 5173:8080 &
kubectl port-forward -n ctf-demo svc/platform-api 8080:8080 &
kubectl port-forward -n ctf-demo svc/a03-injection 9003:8080 &
# ...repeat per challenge on its assigned port (see the root README's table)
```

## Verifying isolation

The included NetworkPolicies were verified on a Calico-backed kind cluster by
running a throwaway pod carrying a challenge's `app` label and confirming DNS
resolves but every other destination times out:

```bash
kubectl run netdebug --image=busybox --restart=Never -n ctf-demo \
  --labels="app=a03-injection" --command -- sleep 3600
kubectl wait --for=condition=Ready pod/netdebug -n ctf-demo --timeout=60s

# DNS resolves (allowed) but the connection itself times out (blocked):
kubectl exec -n ctf-demo netdebug -- nc -zv -w3 db.ctf-demo.svc.cluster.local 5432
kubectl exec -n ctf-demo netdebug -- nc -zv -w3 platform-api.ctf-demo.svc.cluster.local 8080

kubectl delete pod netdebug -n ctf-demo --force --grace-period=0
```

## Teardown

```bash
kubectl delete -k deploy/k8s/overlays/local   # or: kind delete cluster --name ctf-demo
```
