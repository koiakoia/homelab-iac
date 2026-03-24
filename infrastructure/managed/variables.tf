# Managed Layer Variables

variable "proxmox_endpoint" {
  description = "Proxmox API endpoint URL"
  type        = string
  default     = "https://${PROXMOX_NODE1_IP}:8006/"
}

variable "proxmox_api_token" {
  description = "Proxmox API token (set via TF_VAR_proxmox_api_token env var)"
  type        = string
  sensitive   = true
  default     = ""
}
variable "resource_suffix" {
  description = "Suffix appended to resource names"
  type        = string
  default     = ""
}

variable "vm_id_offset" {
  description = "Offset added to VM IDs (0 for production)"
  type        = number
  default     = 0
}
# SSH Key - common across all managed resources
variable "ssh_public_key" {
  description = "SSH public key for VM access"
  type        = string
  default     = "ssh-ed25519 AAAA_YOUR_ED25519_PUBLIC_KEY your-user@your-host"
}
