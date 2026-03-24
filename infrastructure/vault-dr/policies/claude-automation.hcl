# Claude Code Automation - Read-Only Access
# Created: 2026-02-06
# Purpose: Limited-privilege token for Claude Code agent

# Read any KV v2 secret
path "secret/data/*" {
  capabilities = ["read"]
}

# List secret paths (metadata)
path "secret/metadata/*" {
  capabilities = ["list", "read"]
}

# Sign SSH certificates
path "ssh/sign/*" {
  capabilities = ["read", "update"]
}

# Read SSH roles
path "ssh/roles/*" {
  capabilities = ["read"]
}
