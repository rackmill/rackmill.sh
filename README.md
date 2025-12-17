# Rackmill Ubuntu/Debian/RHEL Setup Script

Rackmill is a robust, operator-friendly Bash script for preparing Ubuntu, Debian, and RHEL-family systems for deployment, imaging, or template creation. It enforces canonical package sources, configures system settings, and securely cleans sensitive data, with interactive prompts and clear logging throughout.

## Features
- **Canonical APT Sources Enforcement:**
  - Supports both classic (`sources.list`) and deb822 (`ubuntu.sources`) formats.
  - Audits and guides manual correction of non-standard sources.
- **System Configuration:**
  - Sets hostname, locale, and timezone.
  - Regenerates SSH host keys for security.
- **Cleanup Actions:**
  - Identifies and removes sensitive files (SSH keys, shell history, machine IDs, etc.)
  - Operator must confirm all irreversible actions interactively.
- **Backups:**
  - Automatically backs up critical files before changes.
- **Logging:**
  - Uses `section()` and `step()` for clear, color-coded output.
  - All actions and errors are visible to the operator.

## Intended Use
- Preparing Ubuntu VMs for imaging or template deployment
- Ensuring a clean, secure baseline for new systems
- Operator-driven environments where transparency and control are required

# Usage

As the Operator, observe the script as it runs and respond to any errors or prompts during execution.

While the script runs, follow the interactive prompts to review and confirm each step. Manual approval is required, and intervention may be necessary.

## Quick Start

1. Download and run the script directly.

```bash
clear; cd ~
curl -fsSL https://github.com/rackmill/rackmill.sh/raw/refs/heads/main/rackmill.sh -o rackmill.sh && chmod +x rackmill.sh && sudo ./rackmill.sh
```

**Alternative (if curl is unavailable):**
```bash
clear; cd ~
wget https://github.com/rackmill/rackmill.sh/raw/refs/heads/main/rackmill.sh -O rackmill.sh && chmod +x rackmill.sh && sudo ./rackmill.sh
```

## Manual Setup (If Quick Start is not possible)

1. Copy the entire script content from the project file to your clipboard.
2. Open terminal and type `nano rackmill.sh` to create the empty file.
3. In nano, press:
    `alt` + `\` (go to start)
    `ctrl` + `6` (set marker)
    `alt` + `/` (go to end)
    `ctrl` + `k` (paste)
4. Save and exit nano:
    `ctrl` + `x` (exit)
    `y` (confirm save)
    `enter` (confirm filename)
5. In terminal, make it executable:
    `chmod +x rackmill.sh`
6. Run it:
    `clear; ./rackmill.sh`

## Supported Versions

### Ubuntu
- **LTS Releases**: 14.04 (Trusty), 16.04 (Xenial), 18.04 (Bionic), 20.04 (Focal), 22.04 (Jammy), 24.04 (Noble)
- **Interim Releases**: 25.04 (Plucky Puffin) and others
- **Format**: Classic sources.list (≤23.04), DEB822 format (≥23.10)

### Debian
- **Version 9 (Stretch)**: Archived (uses archive.debian.org, no security updates)
- **Version 10 (Buster)**: Archived (uses archive.debian.org, no security updates)
- **Version 11 (Bullseye)**: Oldoldstable, LTS until 2031
- **Version 12 (Bookworm)**: Oldstable
- **Version 13 (Trixie)**: Current stable
- **Format**: Archive repos (9-10), Classic sources.list (11), DEB822 format (≥12)
- **Note**: Archived releases show APT warnings about missing Release files - this is expected

### RHEL-family
- **AlmaLinux**: 8, 9
- **Rocky Linux**: 8, 9
- **Oracle Linux**: 8, 9
- **CentOS Stream**: 8, 9
- **CentOS 7**: EOL (uses vault.centos.org, requires EPEL for cloud-init)
- **CloudLinux**: 8, 9
- **RHEL**: 8, 9
- **Note**: CentOS 7 repos are automatically migrated to vault.centos.org

## Notes
- No automatic changes to APT sources. Operator must manually edit if needed
- All cleanup actions are irreversible and require explicit confirmation
- Unopinionated about version selection - supports older releases for legacy template requirements

## License
MIT License
