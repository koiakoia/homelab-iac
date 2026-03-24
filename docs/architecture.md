# Infrastructure Architecture

## Network Topology

Two VLANs provide network isolation between public-facing infrastructure and the OKD cluster:

| Network | Bridge | Subnet | Purpose |
|---------|--------|--------|---------|
| LAN | vmbr0 | ${LAN_NETWORK}/24 | VM management, service access |
| Cluster | vmbr1 | ${OKD_NETWORK}/24 | OKD internal (masters, bootstrap) |

### Traffic Flow

```
Internet → Cloudflare Tunnel → pangolin-proxy (Traefik :443)
                                     ↓
              ┌──────────────────────────────────────────────┐
              │  VM services (vault, gitlab, wazuh, minio)   │
              │  OKD services (grafana, argocd, keycloak...) │
              └──────────────────────────────────────────────┘

Tailscale VPN → split DNS (${INTERNAL_DOMAIN}) → pangolin-proxy → backends
LAN clients  → dnsmasq (${INTERNAL_DOMAIN})   → pangolin-proxy → backends
```

**Internal access** (`*.${INTERNAL_DOMAIN}`): Resolved via Tailscale split DNS or LAN dnsmasq to `${PROXY_IP}` (pangolin-proxy), then Traefik routes to backends. TLS via Let's Encrypt wildcard (Cloudflare DNS-01).

**External access** (`gitlab.${DOMAIN}`, `auth.${DOMAIN}`): Cloudflare CNAME → Cloudflare Tunnel → cloudflared on pangolin-proxy → Traefik → backend. Protected by Cloudflare Access with Keycloak OIDC.

## VM and LXC Inventory

| VM ID | Name | IP | Node | Purpose |
|-------|------|-----|------|---------|
| 200 | iac-control | ${IAC_CONTROL_IP} | pve | IaC orchestration, HAProxy LB, dnsmasq, Squid |
| 201 | gitlab-server | ${GITLAB_IP} | pve | GitLab CI/CD |
| 205 | vault-server | ${VAULT_IP} | proxmox-node-2 | HashiCorp Vault (Docker) |
| 107 | pangolin-proxy | ${PROXY_IP} | pve | Traefik + cloudflared (CF Tunnel) |
| 111 | wazuh | ${WAZUH_IP} | proxmox-node-2 | Wazuh SIEM v4.14.1 |
| 109 | seedbox-vm | ${SEEDBOX_IP} | proxmox-node-3 | qBittorrent + gluetun VPN |
| 300 | config-server | ${OKD_GATEWAY} | pve | HA failover (LXC), keepalived BACKUP |
| 301 | minio-bootstrap | ${MINIO_PRIMARY_IP} | proxmox-node-3 | MinIO primary (LXC) |
| 302 | minio-replica | ${MINIO_REPLICA_IP} | pve | MinIO replica (LXC) |

**Golden images**: 9201 (gitlab/pve), 9205 (vault/proxmox-node-2), 9109 (seedbox/proxmox-node-3)

## OKD Cluster (Overwatch)

3-master OKD 4.19 cluster on the internal vmbr1 network:

| Node | IP | Role |
|------|----|------|
| master-0 | ${OKD_MASTER1_IP} | Control plane |
| master-1 | ${OKD_MASTER2_IP} | Control plane |
| master-2 | ${OKD_MASTER3_IP} | Control plane |
| bootstrap | ${OKD_BOOTSTRAP_IP} | Bootstrap (powered off) |

### Supporting Services on iac-control

iac-control (`${OKD_NETWORK_GW}` on vmbr1) provides essential cluster infrastructure:

- **HAProxy** — Load balances OKD API (:6443), Machine Config (:22623), and Ingress (:80/:443) across all 3 masters
- **dnsmasq** — DHCP (${OKD_VIP}-150), DNS (cluster.local + ${OKD_CLUSTER}.${DOMAIN} zones), PXE boot for CoreOS
- **Squid** — Transparent HTTP proxy with domain allowlisting for egress control; iptables redirects port 80 traffic
- **keepalived** — VIP ${OKD_NETWORK_GW} (MASTER on iac-control, BACKUP on config-server LXC)
- **nginx** — PXE server (:8080) serving CoreOS ignition configs

### Air-Gapped Constraints

The OKD cluster has no direct internet egress. All external dependencies must be:

- Mirrored to Harbor container registry (`harbor.${INTERNAL_DOMAIN}`)
- Proxied through Squid (allowlisted domains only)
- Embedded inline (e.g., Grafana dashboards as JSON, not `gnetId` references)

## Proxmox Cluster

| Host | CPU | RAM | Key VMs |
|------|-----|-----|---------|
| pve (${PROXMOX_NODE1_IP}) | 32 | 62GB | iac-control, gitlab-server, pangolin-proxy |
| proxmox-node-2 (${PROXMOX_NODE2_IP}) | 36 | 125GB | vault-server, wazuh |
| proxmox-node-3 (${PROXMOX_NODE3_IP}) | 32 | 125GB | seedbox-vm, minio-bootstrap |

Proxmox snapshots run daily at 1AM UTC (keep 4 snapshots per VM).
