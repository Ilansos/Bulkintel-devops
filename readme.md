# BulkIntel — SOC Bulk Reputation Checker

BulkIntel is a Django-based web application that helps SOC analysts bulk-enrich IOCs (IPs, domains, URLs, hashes, UAs) and surfaces day/week/month leaderboards—delivered through a secure, automated supply chain. Code ships via Jenkins with quality gates (SonarQube) and image/config scanning (Trivy); runtime secrets come from Vault; workloads run on Kubernetes with non-root, read-only filesystems and NetworkPolicies; inbound traffic is funneled through an AWS EC2 proxy deployed via Terraform. Releases are health-checked and auto-rolled back; Nginx metrics feed Prometheus dashboards.

---

## ✨ Features

- **Bulk lookups** for: IP addresses, domains, URLs, file hashes, and user‑agents.  
- **Multi‑provider enrichment** (AbuseIPDB, VirusTotal, BigDataCloud).  
- **Leaderboards**: top queries by **day**, **week**, and **month**, auto‑refreshing (every 5 minutes).  
- **Auth-ready**: Django authentication.  
- **Audit-friendly**: Logging for accountability of IP, user, timestamp.  
- **Containerized**: Docker image for local/dev use.  
- **Kubernetes-ready**: MicroK8s deployment with Vault‑backed secrets.  
- **PostgreSQL** database.
- **Redis**: Cache API responses to reduce the amount of requests to the providers.

> **Tested on:** Ubuntu 22.04. Other distributions may work but weren’t tested.

### 🛡️⚙️ DevSecOps & CI/CD

- **Jenkins multi-stage pipeline**: SAST → **SonarQube** → build → **Trivy** scans (image+config) → push → deploy → post-deploy checks
- **Policy gates (fail fast)**: quality gate must be green; **CRITICAL=0** (block), **HIGH ≤ threshold** (configurable)
- **Safe rollouts**: `kubectl rollout status` with **automatic rollback** on timeout/failure  
- **Secrets hygiene**: runtime injection via **Vault Agent** (KV + PKI), no secrets in images  
- **Observability**: Nginx access → Prometheus metrics (status, route, latency) + dashboards; structured app logs  
- **Controlled ingress**: AWS **EC2 proxy** (NGINX)

---

## 🧪 CI/CD Overview (Jenkins)

BulkIntel uses a multi-branch and multi-stage Jenkins pipeline to build, secure, and ship the app to Kubernetes.

**Differences between dev and prod pipelines:**

1. Dev is deployed to `bulkintel-dev` namespace; prod to `bulkintel`.
2. Dev can be accessed only from the LAN; prod is behind an AWS EC2 proxy.
3. Dev has a more relaxed Trivy HIGH threshold (5 vs 3).

**Stages (high level):**

1. Checkout & Setup – Pull repo, restore caches, set build metadata (git SHA, tag).

2. Static Analysis (SAST) – Run SonarQube analysis.

3. Build & Tag – Build Docker image; tag with git-sha.

4. Security Scans – Trivy (image + config) and third party images scanning.

5. Push – Push image to registry (Local Gitea Server).

6. Deploy – Patch K8s manifests with the new image; apply; verify rollout.

7. Rollback on failure – If rollout verification fails, undo to the previous ReplicaSet.

8. Deployment of AWS EC2 proxy (prod only) – Run Terraform to deploy/update the proxy.

9. Update DNS record (prod only) – Update record to point to the new EC2 instance.

Pipeline runs on dedicated agents (ssh-agent, kubectl-agent, terraform-agent) and uses least-privilege credentials (scoped registry token, Sonar token, read-only K8s deployer SA).

**Post Actions:**

- Always: Archive logs, clean workspace.
- On Success: Send email notification.
- On Failure/Unstable: Open Gitea issue with relevant logs.

---

## 🛡️ Security in the Pipeline (Tools, Policies, Failure Modes)

**SonarQube (Code Quality & SAST):**

- What: Enforces quality gate (bugs, vulnerabilities, coverage).

- Policy: Build fails if gate is red.

  - Thresholds:

    - New code must have 0 Vulnerabilities and 0 Security Hotspots.

    - Overall code must have Security Review Rating of A.

    - Issues are less than 20 (configurable).

    - Duplications less than 10% (configurable).

- Failure behavior: Pipeline aborts when waitForQualityGate() returns FAILED.

**Trivy (Image & Config Scanning):**

- What: Scans built image layers, third party images and K8s manifests for CVEs/misconfig.

- Policy:

  - Block on CRITICAL > 0.
  
  - Request manual approval for HIGH > 3.

  - Block on misconfig CRITICAL > 0 and request manual approval for HIGH > 3 in Deployment/Service/ConfigMaps/HPA YAMLs.

Failure behavior: Jenkins stage fails if counts exceed thresholds.

**Secrets:**

- No secrets in code or images.
- Secrets in CICD (Jenkins) are retrieved from Jenkins Credentials (scoped tokens).
- Secrets in K8S deployments are injected at runtime via Vault Agent (sidecar).

---

## 📦 Architecture (High Level)

![alt text](infrastructure.png "Architecture Diagram")

---

## ✅ Prerequisites

- **Operating System**: Ubuntu 22.04
- **Docker** (for local build/test)
- **MicroK8s** (Kubernetes single-node): with add-ons  
  `metallb`, `dns`, `csi-nfs`, `storage`, `registry`, `metrics-server`  
- **HashiCorp Vault** deployed **in the same K8s cluster** (KV v2 recommended)
- **Prometheus + Grafana** (for metrics)
- **SonarQube** (for SAST)
- **Trivy** (for image/config scanning)
- **Jenkins** (for CI/CD)
- **API keys**:
  - [AbuseIPDB](https://www.abuseipdb.com/)
  - [VirusTotal](https://www.virustotal.com)
  - [BigDataCloud](https://www.bigdatacloud.com)
- **NFS server:** for persistent volumes.

---

## 🔐 Required Configuration (Environment)

BulkIntel reads configuration from environment variables (provided via Hashicorp Vault Secrets).

| Variable | Description | Example |
|---|---|---|
| `DJANGO_SECRET_KEY` | Django secret key | long-random-string |
| `ALLOWED_HOSTS` | Comma-separated hosts | `bulkintel.example.com,127.0.0.1,localhost` |
| `CSRF_TRUSTED_ORIGINS` | Comma-separated URLs | `https://bulkintel.example.com,https://127.0.0.1,https://localhost` |
| `DATABASE_URL` | Full DB URL (preferred) | `postgres://user:pass@postgres-service:5432/bulkintel` |
| `POSTGRES_HOST` | DB host (if not using `DATABASE_URL`) | `postgres-service` |
| `POSTGRES_PORT` | DB port | `5432` |
| `POSTGRES_DB` | DB name | `bulkintel` |
| `POSTGRES_USER` | DB user | `bulkintel` |
| `POSTGRES_PASSWORD` | DB password | `strong-password` |
| `REDIS_HOST` | Redis Host | `redis-service` |
| `REDIS_PORT` | Redis port | `6379` |
| `ABUSEIPDB_KEY` | AbuseIPDB API key | `...` |
| `VIRUSTOTAL_API_KEY` | VirusTotal API key | `...` |
| `BIG_DATA_USERAGENT_KEY` | BigDataCloud API key (or relevant key name) | `...` |
| `DJANGO_SU_NAME` | Django SuperUser Username | `admin` |
| `DJANGO_SU_EMAIL` | Django SuperUser Email | `admin@local.com` |
| `DJANGO_SU_PASS` | Django SuperUser Password | `changeme` |

---

## ☸️ Deployment on Kubernetes

### 1) Install MicroK8s and add-ons

```bash
# Install
sudo snap install microk8s --classic

# Add your user to the group (log out/in after this)
sudo usermod -aG microk8s $USER
sudo chown -f -R $USER ~/.kube

# Enable required add-ons
microk8s enable dns storage registry metrics-server metallb csi-nfs

# Configure metallb with an address pool (example)
# Replace with a free range on your LAN
microk8s enable metallb:192.168.50.240-192.168.50.250
```

### 2) StorageClass notes

- `microk8s-hostpath` is enabled by `storage` (good for quick local PVs).  
- Configure `csi-nfs` and use a `PersistentVolumeClaim` bound to a `StorageClass` for NFS.

### 3) Install HashiCorp Vault

- Assumes Vault is already running in-cluster and unsealed. If not, deploy it first.
- You can find the instructions here: [Hasicorp Vault Deployment](https://developer.hashicorp.com/vault/docs/deploy/kubernetes/helm)

Create a **policy** in Vault and bind it to the `bulkintel-role` so it can read the path(s) below, e.g.:

- `key-value/data/bulkintel` (KV v2 path—note the `/data/` segment for API)

- In Vault, write your app config to the KV v2 path, for example:

```bash
vault kv put key-value/bulkintel \
  DJANGO_SECRET_KEY="..." \
  ALLOWED_HOSTS="bulkintel.your.domain" \
  DEBUG="false" \
  DATABASE_URL="postgres://bulkintel:***@postgres:5432/bulkintel" \
  ABUSEIPDB_KEY="..." \
  VIRUSTOTAL_API_KEY="..." \
  BIG_DATA_USERAGENT_KEY="..."
```

### 4) Configure NFS storage in K8S

You can find instructions on how to do it here: [How to set up NFS server](https://microk8s.io/docs/how-to-nfs)

### 5) App Deployment via Jenkins

- Set up your Jenkins server with the required agents and credentials (see the Jenkinsfile for details).
- Configure the `dev` and `prod` branches in your Git repo with the respective Jenkinsfiles and K8s manifests.
- Update the manifests with your specific settings (e.g., namespace, image registry, resource limits).
- Then, run the pipeline in Jenkins (dev or prod branch).

---

## 🔑 Vault Notes

- Use **KV v2** and ensure your policy includes **read** capability for the app path(s).
- Restart the deployment (or rely on your reload logic) to pick up updated env vars if your app doesn’t hot‑reload them.

---

## 🧰 Developer Tips

- Expose a simple `/healthz` view for liveness/readiness.  
- For large uploads, ensure your reverse proxy (Nginx/Ingress) sets an appropriate `client_max_body_size`.  
- For accurate client IPs behind a proxy, configure `X-Forwarded-For` handling in Nginx/Gunicorn and set Django’s `USE_X_FORWARDED_HOST=True` and `SECURE_PROXY_SSL_HEADER` as needed.

---

## 🧪 Smoke Test

Once deployed (Service has an IP or Ingress works):

1. Visit the app URL and log in with the superuser.  
2. Perform a small bulk query of IPs/domains to validate API key usage.  
3. Check **leaderboards** update after 5 minutes.  
4. Verify database persistence across pod restarts.

---

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## 🙋 Support

- Open an issue in this repository with logs, K8s events, and steps to reproduce.  
- Include your MicroK8s add-on list and Vault/VSO versions when relevant.
