# Sentinel IaC Platform

Infrastructure-as-Code repository for **Project Sentinel** — a hybrid-cloud homelab platform built on Proxmox virtualization, OKD 4.19 Kubernetes, and GitOps automation.

## Platform Overview

Sentinel is a 3-site hybrid-cloud deployment managing 42+ services across:

- **3 Proxmox hosts** — `pve` (32 CPU/62GB), `proxmox-node-2` (36 CPU/125GB), `proxmox-node-3` (32 CPU/125GB)
- **OKD 4.19 cluster** (Overwatch) — 3 master nodes on internal network `${OKD_NETWORK}/24`
- **9 VMs + 2 LXC containers** — purpose-built infrastructure nodes
- **18 internal services** at `*.${INTERNAL_DOMAIN}` + 2 external at `*.${DOMAIN}`

## GitOps Workflow

```
Edit locally → git push → GitLab CI (lint/scan) → Manual trigger (build/provision/configure)
                                                  → ArgoCD auto-sync (overwatch-gitops)
```

- **sentinel-iac** — Ansible, Terraform, Packer. CI runs lint + security scans on every push. Build/provision/configure stages are manual-trigger on `main`.
- **overwatch-gitops** — OKD manifests. Pushing to `main` triggers ArgoCD auto-sync (pushing is deploying).

## Quick Links

| Service | URL | Purpose |
|---------|-----|---------|
| GitLab | [gitlab.${DOMAIN}](https://gitlab.${DOMAIN}) | CI/CD and source control |
| ArgoCD | [argocd.${INTERNAL_DOMAIN}](https://argocd.${INTERNAL_DOMAIN}) | GitOps deployment |
| Grafana | [grafana.${INTERNAL_DOMAIN}](https://grafana.${INTERNAL_DOMAIN}) | Observability dashboards |
| Vault | [vault.${INTERNAL_DOMAIN}](https://vault.${INTERNAL_DOMAIN}) | Secrets management |
| Keycloak | [auth.${INTERNAL_DOMAIN}](https://auth.${INTERNAL_DOMAIN}) | SSO identity provider |
| Harbor | [harbor.${INTERNAL_DOMAIN}](https://harbor.${INTERNAL_DOMAIN}) | Container registry |
| DefectDojo | [defectdojo.${INTERNAL_DOMAIN}](https://defectdojo.${INTERNAL_DOMAIN}) | Vulnerability management |
| Wazuh | [wazuh.${INTERNAL_DOMAIN}](https://wazuh.${INTERNAL_DOMAIN}) | SIEM |
| Homepage | [home.${INTERNAL_DOMAIN}](https://home.${INTERNAL_DOMAIN}) | Service dashboard |

## Repository Structure

```
sentinel-iac/
├── ansible/              # Configuration management
│   ├── inventory/        # Host definitions (hosts.ini)
│   ├── playbooks/        # Per-VM playbooks
│   └── roles/            # Reusable roles (common, docker-host, etc.)
├── infrastructure/       # Provisioning and recovery
│   ├── managed/          # Terraform (OpenTofu) VM definitions
│   ├── modules/vm/       # Reusable VM module
│   ├── bootstrap/        # DR-only bootstrap layer
│   └── recovery/         # Restore scripts (vault, gitlab, minio, etcd)
├── packer/               # Golden image templates
├── ci/                   # CI pipeline includes (security, compliance, DR)
├── pangolin/             # Traefik reverse proxy config (mirrors live)
├── compliance/           # NIST 800-53 artifacts
├── scripts/              # Utility scripts (compliance, vault, mesh)
└── policies/             # Kyverno and security policies
```

## CI Pipeline

**Stages**: `lint` → `security-scan` → `upload-to-defectdojo` → `packer-validate` → `build-templates` → `provision` → `configure` → `compliance-report` → `disaster-recovery`

Automated on every push: yamllint, ansible-lint, gitleaks (secret detection), trivy (IaC + filesystem scan). Results uploaded to DefectDojo for tracking.
