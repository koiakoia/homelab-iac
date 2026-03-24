# =============================================================================
# Packer Template: gitlab-server (VM 201) - GitLab CI/CD
# =============================================================================
# This VM runs GitLab CE (Omnibus) for source control and CI/CD pipelines.
# Located on pve.
#
# After building this template:
#   1. terraform apply (create VM from template)
#   2. ansible-playbook ansible/playbooks/gitlab-server.yml
#   3. Configure external_url, SMTP, and backup settings via gitlab.rb
#   4. Optionally restore from MinIO gitlab-backups/ (app tar + config tar.gz)
#
# Runtime config:
#   - GitLab CE Omnibus package (from packages.gitlab.com repo)
#   - Backup: weekly Sun 3AM UTC, STRATEGY=copy, -> MinIO -> B2 rclone crypt
#   - SKIP list: artifacts, builds, pages, registry, packages, terraform_state
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
  default = "pve"
}

variable "vm_id" {
  type    = number
  default = 9201
}

variable "ssh_password" {
  description = "Temporary SSH password for cloud-init build VM (set via PKR_VAR_ssh_password)"
  type        = string
  sensitive   = true
}

# -----------------------------------------------------------------------------
# Source: Clone from ubuntu-2404-ci base template
# -----------------------------------------------------------------------------

source "proxmox-clone" "gitlab-server" {
  proxmox_url              = var.proxmox_url
  username                 = var.proxmox_token_id
  token                    = var.proxmox_token_secret
  insecure_skip_tls_verify = true

  task_timeout = "5m"

  node     = var.proxmox_node
  vm_id    = var.vm_id
  vm_name  = "gitlab-server-template"
  clone_vm = "ubuntu-2404-ci"

  full_clone       = true
  cores            = 4
  memory           = 16384
  scsi_controller  = "virtio-scsi-pci"

  disks {
    disk_size    = "50G"
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
    ip      = "${VIP_2}/24"
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
  sources = ["source.proxmox-clone.gitlab-server"]

  # Phase 1: Install dependencies for GitLab CE
  provisioner "shell" {
    inline = [
      "sudo apt-get update -y",
      "sudo apt-get install -y curl openssh-server ca-certificates tzdata perl postfix qemu-guest-agent",
      "sudo systemctl enable ssh qemu-guest-agent",
    ]
  }

  # Phase 2: Add GitLab CE repository
  provisioner "shell" {
    inline = [
      "curl -fsSL https://packages.gitlab.com/install/repositories/gitlab/gitlab-ce/script.deb.sh | sudo bash",
    ]
  }

  # Phase 3: Install GitLab CE
  provisioner "shell" {
    inline = [
      "sudo apt-get install -y gitlab-ce",
    ]
  }

  # Phase 4: Cleanup
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
    output     = "gitlab-server-manifest.json"
    strip_path = true
  }
}
