# =============================================================================
# Packer Template: vault-server (VM 205) - Secrets Management
# =============================================================================
# This VM runs HashiCorp Vault in a Docker container for secrets management
# and SSH certificate authority. Located on proxmox-node-2.
#
# After building this template:
#   1. terraform apply (create VM from template)
#   2. ansible-playbook ansible/playbooks/vault-server.yml
#   3. vault operator unseal (manual, Shamir keys required)
#   4. Optionally restore data from MinIO vault-backups/
#
# Runtime config:
#   - Vault image: hashicorp/vault:1.21.2 (Docker)
#   - Data: /opt/vault/data, Config: /etc/vault/config, Logs: /opt/vault/logs
#   - Backup: daily tar.gz -> MinIO vault-backups/ -> B2 rclone crypt
# =============================================================================

packer {
  required_plugins {
    proxmox = {
      version = ">= 1.1.2"
      source  = "github.com/hashicorp/proxmox"
    }
  }
}

# -----------------------------------------------------------------------------
# Variables
# -----------------------------------------------------------------------------

variable "proxmox_url" {
  type    = string
  default = "https://${PROXMOX_NODE1_IP}:8006/api2/json"
}

variable "proxmox_token_id" {
  type    = string
  default = "terraform-prov@pve!api-token"
}

variable "proxmox_token_secret" {
  type      = string
  sensitive = true
}

variable "proxmox_node" {
  type    = string
  default = "proxmox-node-2"
}

variable "vm_id" {
  type    = number
  default = 9205
}

variable "ssh_password" {
  description = "Temporary SSH password for cloud-init build VM (set via PKR_VAR_ssh_password)"
  type        = string
  sensitive   = true
}

# -----------------------------------------------------------------------------
# Source: Clone from ubuntu-2404-ci base template
# -----------------------------------------------------------------------------

source "proxmox-clone" "vault-server" {
  proxmox_url              = var.proxmox_url
  username                 = var.proxmox_token_id
  token                    = var.proxmox_token_secret
  insecure_skip_tls_verify = true

  task_timeout = "5m"

  node     = var.proxmox_node
  vm_id    = var.vm_id
  vm_name  = "vault-server-template"
  clone_vm = "ubuntu-2404-ci"

  full_clone       = true
  cores            = 2
  memory           = 4096
  scsi_controller  = "virtio-scsi-pci"

  disks {
    disk_size    = "32G"
    storage_pool = "local-lvm"
    type         = "scsi"
  }

  network_adapters {
    bridge = "vmbr0"
    model  = "virtio"
  }

  cloud_init              = true
  cloud_init_storage_pool = "local-lvm"

  ipconfig {
    ip      = "${VIP_1}/24"
    gateway = "${GATEWAY_IP}"
  }

  ssh_username = "ubuntu"
  ssh_password = var.ssh_password
  ssh_timeout  = "10m"
}

# -----------------------------------------------------------------------------
# Build
# -----------------------------------------------------------------------------

build {
  sources = ["source.proxmox-clone.vault-server"]

  # Phase 1: Install Docker and dependencies
  provisioner "shell" {
    inline = [
      "sudo apt-get update -y",
      "sudo apt-get install -y docker.io docker-compose-v2 jq curl wget qemu-guest-agent",
      "sudo systemctl enable docker qemu-guest-agent",
      "sudo mkdir -p /opt/vault/data /etc/vault/config /opt/vault/logs",
    ]
  }

  # Phase 2: Cleanup
  provisioner "shell" {
    inline = [
      "sudo apt-get clean",
      "sudo rm -rf /var/lib/apt/lists/*",
      "sudo cloud-init clean --logs",
      "sudo truncate -s 0 /var/log/syslog /var/log/auth.log || true",
      "sync",
    ]
  }

  post-processor "manifest" {
    output     = "vault-server-manifest.json"
    strip_path = true
  }
}
