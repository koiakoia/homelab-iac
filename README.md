# homelab-iac

Production-grade Infrastructure as Code for a Proxmox homelab. Terraform modules, Packer golden images, Ansible roles, and compliance automation — the full stack for treating a homelab like real infrastructure.

This is the IaC backbone of [Project Sentinel](https://github.com/koiakoia), a 3-node Proxmox cluster running an air-gapped OKD (OpenShift) Kubernetes cluster with NIST 800-53 compliance, Wazuh SIEM, HashiCorp Vault, and GitOps via ArgoCD.

## What's In Here

### Ansible (`ansible/`)
11 roles for consistent VM provisioning and configuration:

| Role | What It Does |
|------|-------------|
| `iac-control` | Control plane VM — HAProxy, dnsmasq, Squid proxy, Keepalived |
| `vault-server` | HashiCorp Vault with Docker, TLS, transit auto-unseal |
| `gitlab-server` | GitLab CE with OIDC, container registry, PAT rotation |
| `wazuh-server` | Wazuh manager with custom rules and active response |
| `wazuh-agent` | Agent deployment across all managed VMs |
| `config-server` | DNS/DHCP for the Kubernetes network |
| `minio-bootstrap` | MinIO distributed storage |
| `seedbox` | Media services with VPN tunneling |
| `forgejo-server` | Forgejo git server (GitLab mirror) |
| `pangolin-proxy` | Reverse proxy with Traefik |
| `common` | SSH hardening, CIS baselines, NTP, base packages |

### Terraform (`infrastructure/`)
Proxmox VM lifecycle management with OpenTofu:

- **`modules/vm/`** — Reusable VM module (CPU, memory, disk, network, cloud-init)
- **`bootstrap/`** — Initial infrastructure (GitLab, Vault, config server)
- **`managed/`** — Day-2 VM management
- **`recovery/`** — Disaster recovery scripts (Vault, GitLab, MinIO, etcd restore)

### Packer (`packer/`)
Golden image templates for every VM type — `iac-control`, `vault-server`, `gitlab-server`, `minio-bootstrap`, `seedbox-vm`, `forgejo-server`, and Fedora CoreOS for OKD nodes.

### Compliance (`compliance/`, `scripts/`)
- NIST 800-53 compliance checker (`nist-compliance-check.sh`) — 125 automated controls
- Evidence pipeline for OSCAL artifact generation
- CIS hardening baselines applied via Ansible

### Reverse Proxy (`pangolin/`)
Traefik dynamic routing configs for all internal and external services, including Cloudflare Tunnel integration.

## CI/CD Pipeline

```
lint → security-scan → upload-to-defectdojo → packer-validate → build-templates → provision → configure → compliance-report → disaster-recovery
```

Every push runs linting (yamllint, tflint, ansible-lint), security scanning (Trivy IaC, gitleaks), and compliance validation.

## Getting Started

1. Copy `.env.example` to `.env` and fill in your values
2. Copy `terraform.tfvars.example` to `terraform.tfvars`
3. Update `ansible/inventory/hosts.ini` with your IPs
4. Run Packer to build golden images: `cd packer && packer init . && packer build .`
5. Run Terraform to provision VMs: `cd infrastructure/bootstrap && tofu init && tofu plan`
6. Run Ansible to configure: `cd ansible && ansible-playbook -i inventory/hosts.ini playbooks/site.yml`

All hardcoded values have been replaced with `${VARIABLE}` placeholders — see `.env.example` for the full list.

## Related Repos

- [homelab-gitops](https://github.com/koiakoia/homelab-gitops) — ArgoCD app-of-apps, Kubernetes manifests
- [homelab-compliance](https://github.com/koiakoia/homelab-compliance) — NIST 800-53 OSCAL artifacts and evidence
- [homelab-platform](https://github.com/koiakoia/homelab-platform) — OKD cluster bootstrap and agent framework

## License

Apache 2.0 — see [LICENSE](LICENSE).
