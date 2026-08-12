# Kizashi Helm Chart

Enterprise-grade Helm chart for deploying the Kizashi Endpoint Detection & Response platform on Kubernetes.

## Prerequisites

- Kubernetes 1.25+
- Helm 3.10+
- `kubectl` configured against the target cluster
- An Ingress controller (nginx recommended)
- (Optional) cert-manager for automatic TLS certificate provisioning
- (Optional) Prometheus Operator for ServiceMonitor support

---

## Quick Start

```bash
# Add the chart repository (once hosted)
helm repo add kizashi https://your-charts-repo
helm repo update

# Install with minimal required overrides
helm install kizashi ./deploy/helm/kizashi \
  --set global.postgresql.password=yourpassword \
  --set global.jwt.secret=yourjwtsecret \
  --namespace edr-platform \
  --create-namespace
```

After installation, check the NOTES output for access URLs and credential retrieval commands.

---

## Configuration

### Global Settings

| Key | Default | Description |
|-----|---------|-------------|
| `global.imageRegistry` | `""` | Override container registry for all images |
| `global.imagePullSecrets` | `[]` | Pull secrets for private registries |
| `global.storageClass` | `""` | Storage class for PVCs (empty = cluster default) |
| `global.postgresql.host` | `postgresql` | PostgreSQL host |
| `global.postgresql.port` | `5432` | PostgreSQL port |
| `global.postgresql.database` | `kizashi` | Database name |
| `global.postgresql.user` | `kizashi` | Database user |
| `global.postgresql.password` | `""` | DB password (createSecrets must be true) |
| `global.postgresql.existingSecret` | `""` | Use an existing Secret for DB password |
| `global.postgresql.existingSecretKey` | `postgresql-password` | Key in the existing Secret |
| `global.jwt.secret` | `""` | JWT signing secret (createSecrets must be true) |
| `global.jwt.existingSecret` | `""` | Use an existing Secret for JWT secret |
| `global.jwt.existingSecretKey` | `jwt-secret` | Key in the existing Secret |
| `global.nats.urls` | `[nats://nats-0..., ...]` | NATS cluster URLs (3-node) |

### Secret Management

| Key | Default | Description |
|-----|---------|-------------|
| `createSecrets` | `true` | Create a Secret from plaintext values |
| `secretName` | `kizashi-credentials` | Name of the managed Secret |

**Production recommendation:** set `createSecrets=false` and use `global.postgresql.existingSecret` / `global.jwt.existingSecret` to reference secrets managed by Vault, External Secrets Operator, or another system.

### API Server

| Key | Default | Description |
|-----|---------|-------------|
| `api.replicaCount` | `2` | Number of API replicas |
| `api.image.repository` | `kizashi/api` | Container image |
| `api.image.tag` | `1.0.0` | Image tag |
| `api.resources.requests.cpu` | `250m` | CPU request |
| `api.resources.requests.memory` | `256Mi` | Memory request |
| `api.resources.limits.cpu` | `1000m` | CPU limit |
| `api.resources.limits.memory` | `512Mi` | Memory limit |
| `api.autoscaling.enabled` | `false` | Enable HPA |
| `api.autoscaling.minReplicas` | `2` | HPA minimum |
| `api.autoscaling.maxReplicas` | `10` | HPA maximum |
| `api.autoscaling.targetCPUUtilizationPercentage` | `70` | HPA CPU target |

### Ingestion Server

| Key | Default | Description |
|-----|---------|-------------|
| `ingestion.replicaCount` | `2` | Number of ingestion replicas |
| `ingestion.image.repository` | `kizashi/ingestion` | Container image |
| `ingestion.resources.requests.cpu` | `500m` | CPU request |
| `ingestion.resources.limits.memory` | `1Gi` | Memory limit |
| `ingestion.autoscaling.enabled` | `false` | Enable HPA |

### Detection Engine

| Key | Default | Description |
|-----|---------|-------------|
| `detection.replicaCount` | `2` | Number of detection replicas |
| `detection.image.repository` | `kizashi/detection` | Container image |
| `detection.resources.requests.cpu` | `1000m` | CPU request (detection is CPU-intensive) |
| `detection.resources.limits.memory` | `4Gi` | Memory limit |
| `detection.autoscaling.enabled` | `false` | Enable HPA |

### Frontend

| Key | Default | Description |
|-----|---------|-------------|
| `frontend.replicaCount` | `2` | Number of frontend replicas |
| `frontend.image.repository` | `kizashi/frontend` | Container image |
| `frontend.resources.requests.cpu` | `100m` | CPU request |
| `frontend.resources.limits.memory` | `256Mi` | Memory limit |
| `frontend.autoscaling.enabled` | `false` | Enable HPA |

### Ingress

| Key | Default | Description |
|-----|---------|-------------|
| `ingress.enabled` | `true` | Create an Ingress resource |
| `ingress.className` | `nginx` | Ingress class |
| `ingress.host` | `kizashi.example.com` | Public hostname |
| `ingress.tls.enabled` | `true` | Enable TLS |
| `ingress.tls.secretName` | `kizashi-tls` | TLS secret name |
| `ingress.tls.certManager` | `false` | Add cert-manager annotation |
| `ingress.tls.certManagerIssuer` | `letsencrypt-prod` | cert-manager ClusterIssuer name |

### Service Account

| Key | Default | Description |
|-----|---------|-------------|
| `serviceAccount.create` | `true` | Create a ServiceAccount |
| `serviceAccount.name` | `""` | Override ServiceAccount name |
| `serviceAccount.automountServiceAccountToken` | `false` | Mount API token in pods |

### Monitoring

| Key | Default | Description |
|-----|---------|-------------|
| `monitoring.serviceMonitor.enabled` | `false` | Create Prometheus ServiceMonitors |
| `monitoring.serviceMonitor.namespace` | `monitoring` | Namespace for ServiceMonitors |
| `monitoring.serviceMonitor.interval` | `30s` | Scrape interval |
| `monitoring.grafana.enabled` | `false` | Create Grafana dashboard ConfigMap |

---

## Production Deployment Examples

### Using external secrets (recommended)

```bash
# Create secrets separately (e.g. via External Secrets Operator or Vault)
kubectl create secret generic kizashi-credentials \
  --from-literal=postgresql-password="$(openssl rand -base64 32)" \
  --from-literal=jwt-secret="$(openssl rand -base64 64)" \
  --namespace edr-platform

helm install kizashi ./deploy/helm/kizashi \
  --namespace edr-platform \
  --set createSecrets=false \
  --set global.postgresql.existingSecret=kizashi-credentials \
  --set global.jwt.existingSecret=kizashi-credentials \
  --set ingress.host=kizashi.corp.example.com \
  --set ingress.tls.certManager=true \
  --set ingress.tls.certManagerIssuer=letsencrypt-prod
```

### With autoscaling enabled

```bash
helm install kizashi ./deploy/helm/kizashi \
  --namespace edr-platform \
  --set global.postgresql.password=yourpassword \
  --set global.jwt.secret=yourjwtsecret \
  --set api.autoscaling.enabled=true \
  --set api.autoscaling.maxReplicas=20 \
  --set detection.autoscaling.enabled=true \
  --set detection.autoscaling.maxReplicas=10 \
  --set ingestion.autoscaling.enabled=true
```

### With Prometheus monitoring

```bash
helm install kizashi ./deploy/helm/kizashi \
  --namespace edr-platform \
  --set global.postgresql.password=yourpassword \
  --set global.jwt.secret=yourjwtsecret \
  --set monitoring.serviceMonitor.enabled=true \
  --set monitoring.serviceMonitor.additionalLabels.release=kube-prometheus-stack
```

### Using a private container registry

```bash
# Create pull secret
kubectl create secret docker-registry kizashi-registry \
  --docker-server=registry.corp.example.com \
  --docker-username=robot \
  --docker-password="$REGISTRY_TOKEN" \
  --namespace edr-platform

helm install kizashi ./deploy/helm/kizashi \
  --namespace edr-platform \
  --set global.imageRegistry=registry.corp.example.com \
  --set global.imagePullSecrets[0]=kizashi-registry \
  --set global.postgresql.password=yourpassword \
  --set global.jwt.secret=yourjwtsecret
```

---

## Upgrading

```bash
helm upgrade kizashi ./deploy/helm/kizashi \
  --namespace edr-platform \
  --reuse-values \
  --set api.image.tag=1.1.0 \
  --set frontend.image.tag=1.1.0
```

## Uninstalling

```bash
helm uninstall kizashi --namespace edr-platform

# Remove the namespace (also removes any PVCs)
kubectl delete namespace edr-platform
```

> **Note:** The credentials Secret has `helm.sh/resource-policy: keep` set, so it will
> survive `helm uninstall`. Delete it manually if needed:
> `kubectl delete secret kizashi-credentials -n edr-platform`

---

## Architecture

```
Internet
   |
[Ingress / nginx]
   |          |
   |          +-- /api/ --> [API Service :8080]
   |                             |
   |                        [API Deployment]
   |                         2+ replicas
   |                             |
   +-- /    --> [Frontend]    [PostgreSQL]
               Service :3000      |
               [Frontend       [NATS Cluster]
               Deployment]      3 nodes
               2+ replicas        |
                              [Ingestion]  [Detection]
                              Deployment   Deployment
                              2+ replicas  2+ replicas
```

All internal services use `ClusterIP` and communicate over the cluster network.
The Ingress is the single entry point for external traffic.
