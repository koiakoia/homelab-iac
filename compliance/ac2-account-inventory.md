# iac-control Account Inventory (AC-2)
**System:** iac-control.${DOMAIN} (${IAC_CONTROL_IP})  
**Date:** 2026-02-06  
**Compliance:** NIST 800-53 AC-2

## Shell-Enabled Accounts

### root
- **UID:** 0
- **Shell:** /bin/bash
- **Auth Method:** SSH key only (via Vault-signed certificates)
- **Purpose:** System administration, emergency access
- **Access:** Vault-authenticated principals only
- **Status:** ACTIVE, REQUIRED

### ubuntu
- **UID:** 1000
- **Shell:** /bin/bash
- **Auth Method:** SSH key only (via Vault-signed certificates)
- **Purpose:** Primary administrative account for routine operations
- **Access:** Vault-authenticated principals only
- **Status:** ACTIVE, REQUIRED

### sync
- **UID:** 4
- **Shell:** /bin/sync
- **Auth Method:** N/A (system account)
- **Purpose:** System utility for syncing filesystems
- **Status:** ACTIVE, SYSTEM ACCOUNT

## Service Accounts (No Shell)

### gitlab-runner
- **UID:** 1001
- **Shell:** /usr/sbin/nologin (hardened 2026-02-06)
- **Auth Method:** SSH key (for CI/CD automation)
- **Purpose:** GitLab CI/CD pipeline execution
- **Access:** Automated processes only, no interactive login
- **Status:** ACTIVE, HARDENED

## Authentication Summary

| Account | Interactive Shell | SSH Allowed | Vault-Signed Required | Password Auth |
|---------|------------------|-------------|----------------------|---------------|
| root | Yes | Yes | Yes | No |
| ubuntu | Yes | Yes | Yes | No |
| sync | System only | No | N/A | No |
| gitlab-runner | No | Yes (keys only) | No | No |

## Access Control Mechanisms

1. **Vault SSH CA:** All interactive access requires Vault-signed SSH certificates (30-min TTL)
2. **No Password Auth:** Password authentication disabled system-wide
3. **Service Account Hardening:** gitlab-runner shell set to nologin to prevent interactive sessions
4. **Key-Based Only:** All authentication uses SSH keys or Vault-signed certificates

## Compliance Notes

- ✅ AC-2(1): Automated account management via Vault
- ✅ AC-2(2): Temporary/emergency accounts via short-lived Vault certs
- ✅ AC-2(3): Service accounts disabled for interactive login
- ✅ AC-2(4): Automated audit capability through Vault logging

## Review Schedule
- **Next Review:** 2026-05-06 (quarterly)
- **Owner:** Infrastructure Security Team
